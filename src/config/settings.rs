use std::env;

/// Application settings loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Settings {
    // Server
    pub host: String,
    pub port: u16,

    // MongoDB
    pub mongodb_uri: String,
    pub database_name: String,

    // JWT
    pub jwt_secret: String,
    pub jwt_access_token_expiry_secs: i64,
    pub jwt_refresh_token_expiry_secs: i64,

    // Argon2id parameters
    pub argon2_memory_kb: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,

    // Rate limiting
    pub rate_limit_auth_max: u32,
    pub rate_limit_auth_window_secs: u64,
    pub rate_limit_write_max: u32,
    pub rate_limit_write_window_secs: u64,
    pub rate_limit_read_max: u32,
    pub rate_limit_read_window_secs: u64,

    // Account lockout
    pub max_failed_login_attempts: u32,
    pub lockout_duration_secs: u64,
}

impl Settings {
    /// Load settings from environment variables with sensible defaults.
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            // Server
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .expect("PORT must be a valid u16"),

            // MongoDB
            mongodb_uri: env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
            database_name: env::var("DATABASE_NAME")
                .unwrap_or_else(|_| "rustvault".to_string()),

            // JWT
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "CHANGE_ME_IN_PRODUCTION_super_secret_key_12345".to_string()),
            jwt_access_token_expiry_secs: env::var("JWT_ACCESS_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "900".to_string()) // 15 minutes
                .parse()
                .expect("JWT_ACCESS_TOKEN_EXPIRY_SECS must be a valid i64"),
            jwt_refresh_token_expiry_secs: env::var("JWT_REFRESH_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "604800".to_string()) // 7 days
                .parse()
                .expect("JWT_REFRESH_TOKEN_EXPIRY_SECS must be a valid i64"),

            // Argon2id
            argon2_memory_kb: env::var("ARGON2_MEMORY_KB")
                .unwrap_or_else(|_| "65536".to_string()) // 64MB
                .parse()
                .expect("ARGON2_MEMORY_KB must be a valid u32"),
            argon2_iterations: env::var("ARGON2_ITERATIONS")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .expect("ARGON2_ITERATIONS must be a valid u32"),
            argon2_parallelism: env::var("ARGON2_PARALLELISM")
                .unwrap_or_else(|_| "4".to_string())
                .parse()
                .expect("ARGON2_PARALLELISM must be a valid u32"),

            // Rate limiting
            rate_limit_auth_max: env::var("RATE_LIMIT_AUTH_MAX")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .expect("RATE_LIMIT_AUTH_MAX must be a valid u32"),
            rate_limit_auth_window_secs: env::var("RATE_LIMIT_AUTH_WINDOW_SECS")
                .unwrap_or_else(|_| "900".to_string()) // 15 minutes
                .parse()
                .expect("RATE_LIMIT_AUTH_WINDOW_SECS must be a valid u64"),
            rate_limit_write_max: env::var("RATE_LIMIT_WRITE_MAX")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .expect("RATE_LIMIT_WRITE_MAX must be a valid u32"),
            rate_limit_write_window_secs: env::var("RATE_LIMIT_WRITE_WINDOW_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .expect("RATE_LIMIT_WRITE_WINDOW_SECS must be a valid u64"),
            rate_limit_read_max: env::var("RATE_LIMIT_READ_MAX")
                .unwrap_or_else(|_| "120".to_string())
                .parse()
                .expect("RATE_LIMIT_READ_MAX must be a valid u32"),
            rate_limit_read_window_secs: env::var("RATE_LIMIT_READ_WINDOW_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .expect("RATE_LIMIT_READ_WINDOW_SECS must be a valid u64"),

            // Account lockout
            max_failed_login_attempts: env::var("MAX_FAILED_LOGIN_ATTEMPTS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .expect("MAX_FAILED_LOGIN_ATTEMPTS must be a valid u32"),
            lockout_duration_secs: env::var("LOCKOUT_DURATION_SECS")
                .unwrap_or_else(|_| "3600".to_string()) // 1 hour
                .parse()
                .expect("LOCKOUT_DURATION_SECS must be a valid u64"),
        })
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
