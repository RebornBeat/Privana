use kyber::{
    decapsulate, encapsulate, keypair,
    KyberError, PublicKey, SecretKey,
};
use dilithium::{
    sign, verify, keygen as dilithium_keygen,
    PublicKey as SignPublicKey,
    SecretKey as SignSecretKey,
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, NewAead},
};
use rand::{rngs::OsRng, RngCore};
use ring::digest;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use warp::{
    ws::{WebSocket, Ws},
    Filter,
};

// Constants
const JWT_SECRET: &[u8] = b"your-secret-key";
const DATABASE_URL: &str = "postgres://user:password@localhost/privana";
const DEFAULT_MESSAGE_TTL: i64 = 300; // 5 minutes in seconds

// Types and Structures
#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: i64,
    username: String,
    kyber_public_key: String,    // Post-quantum encryption key
    dilithium_public_key: String, // Post-quantum signature key
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum SecurityLevel {
    Maximum,    // Full quantum-resistant encryption + self-destructing messages
    Standard,   // Regular end-to-end encryption
    Basic       // Basic encryption for countries with restrictions
}

#[derive(Debug, Serialize, Deserialize)]
struct UserLocation {
    country_code: String,
    ip_address: String,
    security_level: SecurityLevel,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignupRequest {
    username: String,
    password: String,
    kyber_public_key: String,
    dilithium_public_key: String,
    country_code: Option<String>,  // Optional: user-provided country
    ip_address: String,           // Client IP address
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse {
    token: String,
    user: User,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    sender: String,
    recipient: String,
    content: String,
    ttl: Option<i64>,          // Time-to-live in seconds
    store_message: bool,       // Whether to store the message
    timestamp: i64,
    message_hash: String,      // SHA-256 hash for integrity verification
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedMessage {
    // ChaCha20-Poly1305 encrypted content
    content: Vec<u8>,
    // Kyber-encapsulated symmetric key
    encapsulated_key: Vec<u8>,
    // Digital signature using Dilithium
    signature: Vec<u8>,
    nonce: Vec<u8>,
    ttl: Option<i64>,
    store_message: bool,
    timestamp: i64,
    // BLAKE3 hash for integrity
    message_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageMetadata {
    sender: String,
    recipient: String,
    timestamp: i64,
    message_type: String,
}

#[derive(Clone)]
struct AppState {
    db: Pool<Postgres>,
    active_connections: Arc<RwLock<HashMap<String, ActiveConnection>>>,
}

#[derive(Clone)]
struct UserKeys {
    kyber_public_key: Vec<u8>,
    dilithium_public_key: Vec<u8>,
}

struct ActiveConnection {
    sender: futures::channel::mpsc::UnboundedSender<WsMessage>,
    keys: UserKeys,
}

// Encryption utilities
struct CryptoUtils;

impl CryptoUtils {
    // Generate Kyber key pair for post-quantum encryption
    fn generate_kyber_keypair() -> Result<(Vec<u8>, Vec<u8>), KyberError> {
        let mut rng = OsRng;
        let (public_key, secret_key) = keypair(&mut rng)?;
        Ok((public_key.to_bytes().to_vec(), secret_key.to_bytes().to_vec()))
    }

    // Generate Dilithium key pair for post-quantum signatures
    fn generate_dilithium_keypair() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let (public_key, secret_key) = dilithium_keygen(&mut rng)?;
        Ok((public_key.to_vec(), secret_key.to_vec()))
    }

    // Calculate message hash using BLAKE3 (faster and more secure than SHA-256)
    fn calculate_message_hash(content: &[u8]) -> String {
        let hash = blake3::hash(content);
        hex::encode(hash.as_bytes())
    }

    // Verify message integrity
    fn verify_message_integrity(content: &[u8], provided_hash: &str) -> bool {
        let calculated_hash = Self::calculate_message_hash(content);
        calculated_hash == provided_hash
    }

    // Encrypt a message using hybrid encryption (post-quantum + symmetric)
    fn encrypt_message(
        content: &[u8],
        recipient_kyber_public_key: &[u8],
        sender_dilithium_secret_key: &[u8],
        ttl: Option<i64>,
        store_message: bool,
    ) -> Result<EncryptedMessage, Box<dyn std::error::Error>> {
        let mut rng = OsRng;

        // Generate a new ChaCha20-Poly1305 key
        let mut chacha_key = [0u8; 32];
        rng.fill_bytes(&mut chacha_key);

        // Encapsulate the symmetric key using Kyber
        let recipient_public_key = PublicKey::from_bytes(recipient_kyber_public_key)?;
        let (encapsulated_key, symmetric_key) = encapsulate(&recipient_public_key, &mut rng)?;

        // Create ChaCha20-Poly1305 cipher
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
        let nonce = {
            let mut n = [0u8; 12];
            rng.fill_bytes(&mut n);
            n
        };

        // Encrypt the content
        let encrypted_content = cipher.encrypt(
            Nonce::from_slice(&nonce),
            content,
        )?;

        // Sign the encrypted content using Dilithium
        let sender_secret_key = SignSecretKey::from_bytes(sender_dilithium_secret_key)?;
        let signature = sign(&encrypted_content, &sender_secret_key, &mut rng)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        let message_hash = Self::calculate_message_hash(&encrypted_content);

        Ok(EncryptedMessage {
            content: encrypted_content,
            encapsulated_key: encapsulated_key.to_vec(),
            signature,
            nonce: nonce.to_vec(),
            ttl,
            store_message,
            timestamp,
            message_hash,
        })
    }

    // Decrypt a message using hybrid decryption
    fn decrypt_message(
        encrypted: &EncryptedMessage,
        recipient_kyber_secret_key: &[u8],
        sender_dilithium_public_key: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Verify the signature first
        let sender_public_key = SignPublicKey::from_bytes(sender_dilithium_public_key)?;
        verify(
            &encrypted.content,
            &encrypted.signature,
            &sender_public_key,
        )?;

        // Verify message integrity
        if !Self::verify_message_integrity(&encrypted.content, &encrypted.message_hash) {
            return Err("Message integrity check failed".into());
        }

        // Decapsulate the symmetric key using Kyber
        let recipient_secret_key = SecretKey::from_bytes(recipient_kyber_secret_key)?;
        let symmetric_key = decapsulate(
            &encrypted.encapsulated_key,
            &recipient_secret_key,
        )?;

        // Create ChaCha20-Poly1305 cipher
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&symmetric_key));

        // Decrypt the content
        let decrypted_content = cipher.decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.content.as_ref(),
        )?;

        Ok(decrypted_content)
    }
}

// Database operations
impl AppState {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(DATABASE_URL)
            .await?;

        // Initialize database tables with updated schema
        sqlx::query(
            r#"

            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                kyber_public_key TEXT NOT NULL,
                dilithium_public_key TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS user_locations (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id),
                country_code VARCHAR(2) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                security_level VARCHAR(20) NOT NULL,
                last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id)
            );

            CREATE TABLE IF NOT EXISTS message_metadata (
                id BIGSERIAL PRIMARY KEY,
                sender VARCHAR(255) NOT NULL,
                recipient VARCHAR(255) NOT NULL,
                timestamp BIGINT NOT NULL,
                message_type VARCHAR(50) NOT NULL,
                FOREIGN KEY (sender) REFERENCES users(username),
                FOREIGN KEY (recipient) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS stored_messages (
                id BIGSERIAL PRIMARY KEY,
                sender VARCHAR(255) NOT NULL,
                recipient VARCHAR(255) NOT NULL,
                encrypted_content BYTEA NOT NULL,
                encapsulated_key BYTEA NOT NULL,
                signature BYTEA NOT NULL,
                nonce BYTEA NOT NULL,
                timestamp BIGINT NOT NULL,
                expiry_time BIGINT,
                message_hash TEXT NOT NULL,
                FOREIGN KEY (sender) REFERENCES users(username),
                FOREIGN KEY (recipient) REFERENCES users(username)
            );
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            db: pool,
            active_connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    // Update create_user to handle the new key format
    async fn create_user(
        &self,
        signup: SignupRequest,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let password_hash = hash(signup.password.as_bytes(), DEFAULT_COST)?;

        // Verify location
        let location = self.verify_location(&signup.ip_address).await?;

        // Start transaction
        let mut tx = self.db.begin().await?;

        // Create user
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (
                username, password_hash,
                kyber_public_key, dilithium_public_key
            )
            VALUES ($1, $2, $3, $4)
            RETURNING id, username, kyber_public_key, dilithium_public_key
            "#,
            signup.username,
            password_hash,
            signup.kyber_public_key,
            signup.dilithium_public_key,
        )
        .fetch_one(&mut tx)
        .await?;

        // Store location information
        sqlx::query!(
            r#"
            INSERT INTO user_locations (
                user_id, country_code, ip_address, security_level
            )
            VALUES ($1, $2, $3, $4)
            "#,
            user.id,
            location.country_code,
            location.ip_address,
            format!("{:?}", location.security_level),
        )
        .execute(&mut tx)
        .await?;

        tx.commit().await?;

        Ok(user)
    }

    async fn verify_location(
        &self,
        ip_address: &str,
    ) -> Result<UserLocation, Box<dyn std::error::Error>> {
        // Use a geolocation service (like MaxMind) to verify IP
        let location = match geoip2::lookup_ip(ip_address) {
            Ok(loc) => loc,
            Err(_) => return Err("Failed to verify location".into()),
        };

        let country_code = location.country.code.to_uppercase();
        let security_level = match country_code.as_str() {
            "DO" => SecurityLevel::Maximum,  // Dominican Republic
            // Add more countries as they become available
            _ => SecurityLevel::Standard,
        };

        Ok(UserLocation {
            country_code,
            ip_address: ip_address.to_string(),
            security_level,
        })
    }

    async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
        ip_address: &str,
    ) -> Result<Option<(User, SecurityLevel)>, Box<dyn std::error::Error>> {
        let user_data = sqlx::query!(
            r#"
            SELECT u.*, ul.country_code, ul.security_level
            FROM users u
            JOIN user_locations ul ON u.id = ul.user_id
            WHERE u.username = $1
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(user) = user_data {
            if verify(password, &user.password_hash)? {
                // Verify current location
                let current_location = self.verify_location(ip_address).await?;

                // Check if security level needs to be adjusted
                let security_level = if current_location.country_code == user.country_code {
                    user.security_level.parse::<SecurityLevel>().unwrap_or(SecurityLevel::Standard)
                } else {
                    SecurityLevel::Standard
                };

                Ok(Some((
                    User {
                        id: user.id,
                        username: user.username,
                        kyber_public_key: user.kyber_public_key,
                        dilithium_public_key: user.dilithium_public_key,
                    },
                    security_level,
                )))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn store_message_metadata(
        &self,
        metadata: &MessageMetadata,
        security_level: &SecurityLevel,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Only store metadata for non-Maximum security or when explicitly requested
        if !matches!(security_level, SecurityLevel::Maximum) {
            sqlx::query!(
                r#"
                INSERT INTO message_metadata (
                    sender, recipient, timestamp, message_type, security_level
                )
                VALUES ($1, $2, $3, $4, $5)
                "#,
                metadata.sender,
                metadata.recipient,
                metadata.timestamp,
                metadata.message_type,
                format!("{:?}", security_level),
            )
            .execute(&self.db)
            .await?;
        }

        Ok(())
    }

    async fn store_persistent_message(
        &self,
        sender: &str,
        recipient: &str,
        encrypted_msg: &EncryptedMessage,
        security_level: &SecurityLevel,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Only store messages for non-Maximum security or when explicitly requested
        if !matches!(security_level, SecurityLevel::Maximum) || encrypted_msg.store_message {
            let expiry_time = encrypted_msg.ttl.map(|ttl| encrypted_msg.timestamp + ttl);

            sqlx::query!(
                r#"
                INSERT INTO stored_messages (
                    sender, recipient, encrypted_content,
                    encapsulated_key, signature, nonce,
                    timestamp, expiry_time, message_hash,
                    security_level
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                "#,
                sender,
                recipient,
                &encrypted_msg.content,
                &encrypted_msg.encapsulated_key,
                &encrypted_msg.signature,
                &encrypted_msg.nonce,
                encrypted_msg.timestamp,
                expiry_time,
                &encrypted_msg.message_hash,
                format!("{:?}", security_level),
            )
            .execute(&self.db)
            .await?;
        }

        Ok(())
    }

    async fn get_public_keys(
        &self,
        username: &str,
    ) -> Result<UserKeys, Box<dyn std::error::Error>> {
        let keys = sqlx::query!(
            r#"
            SELECT kyber_public_key, dilithium_public_key
            FROM users WHERE username = $1
            "#,
            username
        )
        .fetch_one(&self.db)
        .await?;

        Ok(UserKeys {
            kyber_public_key: hex::decode(&keys.kyber_public_key)?,
            dilithium_public_key: hex::decode(&keys.dilithium_public_key)?,
        })
    }

    async fn cleanup_expired_messages(&self) -> Result<(), Box<dyn std::error::Error>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        sqlx::query!(
            r#"
            DELETE FROM stored_messages
            WHERE expiry_time IS NOT NULL AND expiry_time <= $1
            "#,
            current_time,
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }
}

// API Routes
async fn handle_signup(
    state: Arc<AppState>,
    signup: SignupRequest,
) -> Result<impl Reply, warp::Rejection> {
    match state.create_user(signup).await {
        Ok(user) => {
            let claims = Claims {
                sub: user.username.clone(),
                exp: (SystemTime::now() + std::time::Duration::from_secs(86400))
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as usize,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(JWT_SECRET),
            )
            .unwrap();

            Ok(warp::reply::json(&LoginResponse { token, user }))
        }
        Err(_) => Err(warp::reject::custom(AuthError)),
    }
}

// WebSocket handler
async fn handle_websocket(
    ws: WebSocket,
    state: AppState,
    username: String,
    security_level: SecurityLevel,
) {
    let (ws_sender, mut ws_receiver) = ws.split();
    let (sender, receiver) = futures::channel::mpsc::unbounded();

    // Fetch user's keys from the database
    let user_keys = match sqlx::query!(
        "SELECT kyber_public_key, dilithium_public_key FROM users WHERE username = $1",
        username
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(keys) => UserKeys {
            kyber_public_key: hex::decode(&keys.kyber_public_key).unwrap_or_default(),
            dilithium_public_key: hex::decode(&keys.dilithium_public_key).unwrap_or_default(),
        },
        Err(_) => return,
    };

    // Store the sender and keys in active connections
    state.active_connections.write().await.insert(
        username.clone(),
        ActiveConnection {
            sender,
            keys: user_keys.clone(),
            security_level: security_level.clone(),
        },
    );

    // Forward messages from the receiver to the WebSocket
    let forward_task = receiver.map(Ok).forward(ws_sender);
    tokio::spawn(forward_task);

    // Handle incoming messages
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(WsMessage::Text(text)) => {
                let message: Message = match serde_json::from_str(&text) {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };

                // Verify message integrity for Maximum security level
                if matches!(security_level, SecurityLevel::Maximum) {
                    if !CryptoUtils::verify_message_integrity(
                        message.content.as_bytes(),
                        &message.message_hash
                    ) {
                        continue;
                    }
                }

                // Get recipient's connection and keys
                let recipient_conn = state
                    .active_connections
                    .read()
                    .await
                    .get(&message.recipient)
                    .cloned();

                // Get recipient's public keys (from active connection or database)
                let recipient_keys = if let Some(conn) = &recipient_conn {
                    conn.keys.clone()
                } else {
                    match sqlx::query!(
                        "SELECT kyber_public_key, dilithium_public_key FROM users WHERE username = $1",
                        message.recipient
                    )
                    .fetch_one(&state.db)
                    .await {
                        Ok(keys) => UserKeys {
                            kyber_public_key: hex::decode(&keys.kyber_public_key).unwrap_or_default(),
                            dilithium_public_key: hex::decode(&keys.dilithium_public_key).unwrap_or_default(),
                        },
                        Err(_) => continue,
                    }
                };

                // Choose encryption method based on security level
                let encrypted = match security_level {
                    SecurityLevel::Maximum => {
                        CryptoUtils::encrypt_message(
                            message.content.as_bytes(),
                            &recipient_keys.kyber_public_key,
                            &user_keys.dilithium_public_key,
                            message.ttl,
                            message.store_message,
                        ).unwrap_or_else(|_| return)
                    },
                    SecurityLevel::Standard => {
                        CryptoUtils::encrypt_standard_message(
                            message.content.as_bytes(),
                            &recipient_keys.kyber_public_key,
                            message.ttl,
                            message.store_message,
                        ).unwrap_or_else(|_| return)
                    },
                    SecurityLevel::Basic => {
                        CryptoUtils::encrypt_basic_message(
                            message.content.as_bytes(),
                            message.store_message,
                        ).unwrap_or_else(|_| return)
                    },
                };

                // Store metadata and message according to security level
                let metadata = MessageMetadata {
                    sender: username.clone(),
                    recipient: message.recipient.clone(),
                    timestamp: encrypted.timestamp,
                    message_type: "text".to_string(),
                };

                let _ = state.store_message_metadata(&metadata, &security_level).await;

                if message.store_message {
                    let _ = state.store_persistent_message(
                        &username,
                        &message.recipient,
                        &encrypted,
                        &security_level,
                    ).await;
                }

                // Forward to recipient if online
                if let Some(recipient_conn) = recipient_conn {
                    let _ = recipient_conn.sender.unbounded_send(WsMessage::Text(
                        serde_json::to_string(&encrypted).unwrap(),
                    ));
                }
            }
            _ => break,
        }
    }

    // Clean up connection
    state.active_connections.write().await.remove(&username);
}

// Periodic cleanup task
async fn run_cleanup_task(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Run every 5 minutes
    loop {
        interval.tick().await;
        if let Err(e) = state.cleanup_expired_messages().await {
            eprintln!("Error cleaning up expired messages: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AppState::new().await?);
    let state_clone = state.clone();

    // Start the cleanup task
    tokio::spawn(run_cleanup_task(state.clone()));

    // API Routes
    let state_filter = warp::any().map(move || state.clone());

    // Signup route
    let signup = warp::path("signup")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(handle_signup);

    // Login route
    let login = warp::path("login")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|credentials: LoginCredentials, state: Arc<AppState>| async move {
            match state.authenticate_user(&credentials.username, &credentials.password).await {
                Ok(Some(user)) => {
                    let claims = Claims {
                        sub: user.username.clone(),
                        exp: (SystemTime::now() + std::time::Duration::from_secs(86400))
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as usize,
                    };

                    let token = encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(JWT_SECRET),
                    )
                    .unwrap();

                    Ok(warp::reply::json(&LoginResponse { token, user }))
                }
                Ok(None) => Err(warp::reject::custom(AuthError)),
                Err(_) => Err(warp::reject::custom(AuthError)),
            }
        });

    // WebSocket route with authentication
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(warp::header("authorization"))
        .and(state_filter.clone())
        .and_then(|ws: Ws, auth: String, state: Arc<AppState>| async move {
            let token = auth.replace("Bearer ", "");
            match decode::<Claims>(
                &token,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::default(),
            ) {
                Ok(token_data) => Ok(ws.on_upgrade(move |socket| {
                    handle_websocket(socket, (*state).clone(), token_data.claims.sub)
                })),
                Err(_) => Err(warp::reject::custom(AuthError)),
            }
        });

    // Retrieve stored messages route
    let get_stored_messages = warp::path("messages")
        .and(warp::get())
        .and(warp::header("authorization"))
        .and(warp::query::<MessageQuery>())
        .and(state_filter.clone())
        .and_then(
            |auth: String, query: MessageQuery, state: Arc<AppState>| async move {
                let token = auth.replace("Bearer ", "");
                match decode::<Claims>(
                    &token,
                    &DecodingKey::from_secret(JWT_SECRET),
                    &Validation::default(),
                ) {
                    Ok(token_data) => {
                        let messages = state
                            .get_stored_messages(&token_data.claims.sub, &query)
                            .await
                            .map_err(|_| warp::reject::custom(AuthError))?;
                        Ok(warp::reply::json(&messages))
                    }
                    Err(_) => Err(warp::reject::custom(AuthError)),
                }
            },
        );

    // CORS configuration
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST"])
        .allow_headers(vec!["content-type", "authorization"]);

    // Combine all routes
    let routes = signup
        .or(login)
        .or(ws_route)
        .or(get_stored_messages)
        .with(cors)
        .recover(handle_rejection);

    // Start the server
    println!("Starting server on 127.0.0.1:3030");
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;

    Ok(())
}

// Additional types and handlers
#[derive(Debug, Deserialize)]
struct LoginCredentials {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct MessageQuery {
    since: Option<i64>,
    limit: Option<i32>,
}

#[derive(Debug)]
struct AuthError;
impl warp::reject::Reject for AuthError {}

async fn handle_rejection(err: warp::Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if err.find::<AuthError>().is_some() {
        code = StatusCode::UNAUTHORIZED;
        message = "Invalid credentials";
    } else {
        eprintln!("unhandled error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    let json = warp::reply::json(&ErrorResponse {
        message: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

// Implementation for message retrieval
impl AppState {
    async fn get_stored_messages(
        &self,
        username: &str,
        query: &MessageQuery,
    ) -> Result<Vec<MessageMetadata>, Box<dyn std::error::Error>> {
        let since = query.since.unwrap_or(0);
        let limit = query.limit.unwrap_or(100).max(1).min(1000);

        let metadata = sqlx::query_as!(
            MessageMetadata,
            r#"
            SELECT sender, recipient, timestamp, message_type
            FROM message_metadata
            WHERE (sender = $1 OR recipient = $1)
            AND timestamp > $2
            ORDER BY timestamp DESC
            LIMIT $3
            "#,
            username,
            since,
            limit as i64,
        )
        .fetch_all(&self.db)
        .await?;

        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_message_integrity() {
        let content = "test message";
        let hash = EncryptionUtils::calculate_message_hash(content);
        assert!(EncryptionUtils::verify_message_integrity(content, &hash));
    }

    #[tokio::test]
    async fn test_message_encryption() {
        // Generate a test key pair
        let (private_key, public_key) = EncryptionUtils::generate_key_pair().unwrap();

        // Test message
        let content = "test message";
        let encrypted = EncryptionUtils::encrypt_message_for_recipient(
            content,
            &public_key,
            Some(300),
            false,
        ).unwrap();

        // Verify the message hash
        assert!(EncryptionUtils::verify_message_integrity(
            content,
            &encrypted.message_hash
        ));
    }
}
