CREATE TABLE IF NOT EXISTS users(
  id UUID PRIMARY KEY,
  username VARCHAR(32) UNIQUE,
  email_address VARCHAR(255) UNIQUE,
  password_hash VARCHAR(255)
);

