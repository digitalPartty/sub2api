-- 072_add_kiro_platform.sql
-- 添加 Kiro 平台支持

-- 1. 更新 accounts 表的平台类型约束
ALTER TABLE accounts
DROP CONSTRAINT IF EXISTS accounts_platform_check;

ALTER TABLE accounts
ADD CONSTRAINT accounts_platform_check
CHECK (platform IN ('anthropic', 'openai', 'gemini', 'antigravity', 'sora', 'kiro'));

-- 2. 为现有 Kiro 账号添加索引 (如果有的话)
CREATE INDEX IF NOT EXISTS idx_accounts_platform_kiro
ON accounts(platform)
WHERE platform = 'kiro' AND deleted_at IS NULL;

-- 3. 添加注释
COMMENT ON CONSTRAINT accounts_platform_check ON accounts IS
'Platform must be one of: anthropic, openai, gemini, antigravity, sora, kiro';
