CREATE TABLE v2_conversations (
    topic TEXT NOT NULL PRIMARY KEY,
    created_at_ns BIGINT NOT NULL,
    peer_address INTEGER NOT NULL,
    envelope_bytes BLOB NOT NULL
);
