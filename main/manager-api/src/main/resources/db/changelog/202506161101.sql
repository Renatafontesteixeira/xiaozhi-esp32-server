-- TiDB cannot change the collation of indexed columns.
-- Keep the existing utf8mb4_unicode_ci ordering for this indexed pair on TiDB.
SET @plugin_mapping_ddl = IF(
    LOCATE('TiDB', VERSION()) > 0 AND (
        SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ai_agent_plugin_mapping'
          AND COLUMN_NAME IN ('agent_id', 'plugin_id')
          AND COLLATION_NAME = 'utf8mb4_unicode_ci'
    ) = 2,
    'ALTER TABLE ai_agent_plugin_mapping CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci',
    'ALTER TABLE ai_agent_plugin_mapping CONVERT TO CHARACTER SET utf8mb4'
);
PREPARE plugin_mapping_stmt FROM @plugin_mapping_ddl;
EXECUTE plugin_mapping_stmt;
DEALLOCATE PREPARE plugin_mapping_stmt;
