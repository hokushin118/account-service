-- init.sql
CREATE USER cba WITH PASSWORD 'pa$$wOrd123!';
CREATE DATABASE account_db OWNER cba;
GRANT ALL PRIVILEGES ON DATABASE account_db TO cba;

-- The following lines are CRUCIAL for pg_hba.conf
ALTER SYSTEM SET default_password_encryption = 'scram-sha-256'; --Good to be explicit
ALTER SYSTEM SET pg_hba_conf_defaults = '{ "host all all 0.0.0.0/0 scram-sha-256" }';
SELECT pg_reload_conf();
