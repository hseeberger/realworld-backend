CREATE TABLE
  IF NOT EXISTS user (
    id BLOB PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    bio TEXT,
    password_hash TEXT
  )