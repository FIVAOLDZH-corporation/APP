-- Disable foreign keys temporarily to avoid conflicts
SET session_replication_role = replica;

-- TRUNCATE TABLE cards RESTART IDENTITY CASCADE;
-- TRUNCATE TABLE columns RESTART IDENTITY CASCADE;
-- TRUNCATE TABLE boards RESTART IDENTITY CASCADE;

DROP TABLE cards;
DROP TABLE columns;
DROP TABLE boards;

SET session_replication_role = DEFAULT;
