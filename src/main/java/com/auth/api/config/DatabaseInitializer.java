//src/main/java/com/auth/api/config/DatabaseInitializer.java
package com.auth.api.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class DatabaseInitializer {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @PostConstruct
    public void init() {
        String createAuditLogTriggerTable = """
            CREATE TABLE IF NOT EXISTS audit_log_trigger (
                id SERIAL PRIMARY KEY,
                table_name VARCHAR(50),
                operation VARCHAR(10),
                old_data JSONB,
                new_data JSONB,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """;
        jdbcTemplate.execute(createAuditLogTriggerTable);

        String createAuditTriggerFunction = """
            CREATE OR REPLACE FUNCTION audit_trigger_function()
            RETURNS TRIGGER AS $$
            BEGIN
                INSERT INTO audit_log_trigger (table_name, operation, old_data, new_data)
                VALUES (
                    TG_TABLE_NAME,
                    TG_OP,
                    row_to_json(OLD),
                    row_to_json(NEW)
                );
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        """;
        jdbcTemplate.execute(createAuditTriggerFunction);

        String createUserAuditTrigger = """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger WHERE tgname = 'user_audit_trigger'
                ) THEN
                    CREATE TRIGGER user_audit_trigger
                    AFTER INSERT OR UPDATE OR DELETE ON users
                    FOR EACH ROW
                    EXECUTE FUNCTION audit_trigger_function();
                END IF;
            END;
            $$;
        """;
        jdbcTemplate.execute(createUserAuditTrigger);
    }
}