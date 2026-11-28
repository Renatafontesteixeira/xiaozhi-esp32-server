-- 批量清理 ai_model_provider 中的 sample_rate 字段定义
-- Remove each matching object without JSON_TABLE, which TiDB 8.5 does not support.
UPDATE ai_model_provider AS provider
JOIN (
    WITH RECURSIVE cleaned (id, fields) AS (
        SELECT id, fields
        FROM ai_model_provider
        WHERE model_type = 'TTS'
          AND JSON_SEARCH(fields, 'one', 'sample!_rate', '!', '$[*].key') IS NOT NULL
        UNION ALL
        SELECT id,
            JSON_REMOVE(fields, REPLACE(
                JSON_UNQUOTE(JSON_SEARCH(fields, 'one', 'sample!_rate', '!', '$[*].key')), '.key', ''
            ))
        FROM cleaned
        WHERE JSON_SEARCH(fields, 'one', 'sample!_rate', '!', '$[*].key') IS NOT NULL
    )
    SELECT id, fields FROM cleaned
    WHERE JSON_SEARCH(fields, 'one', 'sample!_rate', '!', '$[*].key') IS NULL
) AS filtered ON provider.id = filtered.id
SET provider.fields = filtered.fields;

-- 清理 config_json 顶层的 sample_rate
UPDATE `ai_model_config`
SET `config_json` = JSON_REMOVE(`config_json`, '$.sample_rate')
WHERE `model_type` = 'TTS'
  AND JSON_EXTRACT(`config_json`, '$.sample_rate') IS NOT NULL;

-- 清理Minimax流式TTS的sample_rate参数（位于audio_setting内部）
UPDATE `ai_model_config` SET 
`config_json` = JSON_SET(`config_json`, '$.audio_setting', JSON_REMOVE(JSON_EXTRACT(`config_json`, '$.audio_setting'), '$.sample_rate'))
WHERE `id` = 'TTS_MinimaxStreamTTS'
AND JSON_EXTRACT(`config_json`, '$.audio_setting.sample_rate') IS NOT NULL;