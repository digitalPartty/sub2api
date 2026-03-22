package service

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

const (
	kiroTokenRefreshSkew = 3 * time.Minute
	kiroTokenCacheSkew   = 5 * time.Minute
	kiroLockWaitTime     = 200 * time.Millisecond
)

// KiroTokenCache Token 缓存接口（复用 GeminiTokenCache 接口定义）
type KiroTokenCache = GeminiTokenCache

// KiroTokenProvider 管理 Kiro OAuth 账户的 access_token
type KiroTokenProvider struct {
	accountRepo      AccountRepository
	tokenCache       KiroTokenCache
	kiroOAuthService *KiroOAuthService
}

func NewKiroTokenProvider(
	accountRepo AccountRepository,
	tokenCache KiroTokenCache,
	kiroOAuthService *KiroOAuthService,
) *KiroTokenProvider {
	return &KiroTokenProvider{
		accountRepo:      accountRepo,
		tokenCache:       tokenCache,
		kiroOAuthService: kiroOAuthService,
	}
}

// GetAccessToken 获取有效的 access_token
func (p *KiroTokenProvider) GetAccessToken(ctx context.Context, account *Account) (string, error) {
	if account == nil {
		return "", errors.New("account is nil")
	}
	if account.Platform != PlatformKiro {
		return "", errors.New("not a kiro account")
	}

	// upstream 类型：直接从 credentials 读取 api_key，不走 OAuth 刷新流程
	if account.Type == AccountTypeUpstream {
		apiKey := account.GetCredential("api_key")
		if apiKey == "" {
			return "", errors.New("upstream account missing api_key in credentials")
		}
		return apiKey, nil
	}

	if account.Type != AccountTypeOAuth {
		return "", errors.New("not a kiro oauth account")
	}

	cacheKey := KiroTokenCacheKey(account)

	// 1. 先尝试缓存
	if p.tokenCache != nil {
		if token, err := p.tokenCache.GetAccessToken(ctx, cacheKey); err == nil && strings.TrimSpace(token) != "" {
			slog.Debug("kiro_token_cache_hit", "account_id", account.ID)
			return token, nil
		} else if err != nil {
			slog.Warn("kiro_token_cache_get_failed", "account_id", account.ID, "error", err)
		}
	}

	slog.Debug("kiro_token_cache_miss", "account_id", account.ID)

	// 2. 如果即将过期则刷新
	expiresAt := account.GetCredentialAsTime("expires_at")
	needsRefresh := expiresAt == nil || time.Until(*expiresAt) <= kiroTokenRefreshSkew
	refreshFailed := false
	if needsRefresh && p.tokenCache != nil {
		locked, lockErr := p.tokenCache.AcquireRefreshLock(ctx, cacheKey, 30*time.Second)
		if lockErr == nil && locked {
			defer func() { _ = p.tokenCache.ReleaseRefreshLock(ctx, cacheKey) }()

			// 拿到锁后再次检查缓存（另一个 worker 可能已刷新）
			if token, err := p.tokenCache.GetAccessToken(ctx, cacheKey); err == nil && strings.TrimSpace(token) != "" {
				return token, nil
			}

			// 从数据库获取最新账户信息
			fresh, err := p.accountRepo.GetByID(ctx, account.ID)
			if err == nil && fresh != nil {
				account = fresh
			}
			expiresAt = account.GetCredentialAsTime("expires_at")
			if expiresAt == nil || time.Until(*expiresAt) <= kiroTokenRefreshSkew {
				if p.kiroOAuthService == nil {
					slog.Warn("kiro_oauth_service_not_configured", "account_id", account.ID)
					refreshFailed = true
				} else {
					tokenInfo, err := p.kiroOAuthService.RefreshAccountToken(ctx, account)
					if err != nil {
						slog.Warn("kiro_token_refresh_failed", "account_id", account.ID, "error", err)
						refreshFailed = true
					} else {
						// 构建新 credentials，保留原有字段
						newCredentials := make(map[string]any)
						for k, v := range account.Credentials {
							newCredentials[k] = v
						}
						newCredentials["access_token"] = tokenInfo.AccessToken
						newCredentials["token_type"] = tokenInfo.TokenType
						newCredentials["expires_in"] = strconv.FormatInt(tokenInfo.ExpiresIn, 10)
						newCredentials["expires_at"] = strconv.FormatInt(tokenInfo.ExpiresAt, 10)
						if tokenInfo.RefreshToken != "" {
							newCredentials["refresh_token"] = tokenInfo.RefreshToken
						}
						if tokenInfo.Scope != "" {
							newCredentials["scope"] = tokenInfo.Scope
						}
						account.Credentials = newCredentials
						if updateErr := p.accountRepo.Update(ctx, account); updateErr != nil {
							slog.Error("kiro_token_provider_update_failed", "account_id", account.ID, "error", updateErr)
						}
						expiresAt = account.GetCredentialAsTime("expires_at")
					}
				}
			}
		} else if lockErr != nil {
			// Redis 错误导致无法获取锁，降级为无锁刷新
			slog.Warn("kiro_token_lock_failed_degraded_refresh", "account_id", account.ID, "error", lockErr)

			if ctx.Err() != nil {
				return "", ctx.Err()
			}

			// 从数据库获取最新账户信息
			if p.accountRepo != nil {
				fresh, err := p.accountRepo.GetByID(ctx, account.ID)
				if err == nil && fresh != nil {
					account = fresh
				}
			}
			expiresAt = account.GetCredentialAsTime("expires_at")

			if expiresAt == nil || time.Until(*expiresAt) <= kiroTokenRefreshSkew {
				if p.kiroOAuthService == nil {
					slog.Warn("kiro_oauth_service_not_configured", "account_id", account.ID)
					refreshFailed = true
				} else {
					tokenInfo, err := p.kiroOAuthService.RefreshAccountToken(ctx, account)
					if err != nil {
						slog.Warn("kiro_token_refresh_failed_degraded", "account_id", account.ID, "error", err)
						refreshFailed = true
					} else {
						newCredentials := make(map[string]any)
						for k, v := range account.Credentials {
							newCredentials[k] = v
						}
						newCredentials["access_token"] = tokenInfo.AccessToken
						newCredentials["token_type"] = tokenInfo.TokenType
						newCredentials["expires_in"] = strconv.FormatInt(tokenInfo.ExpiresIn, 10)
						newCredentials["expires_at"] = strconv.FormatInt(tokenInfo.ExpiresAt, 10)
						if tokenInfo.RefreshToken != "" {
							newCredentials["refresh_token"] = tokenInfo.RefreshToken
						}
						if tokenInfo.Scope != "" {
							newCredentials["scope"] = tokenInfo.Scope
						}
						account.Credentials = newCredentials
						if updateErr := p.accountRepo.Update(ctx, account); updateErr != nil {
							slog.Error("kiro_token_provider_update_failed", "account_id", account.ID, "error", updateErr)
						}
						expiresAt = account.GetCredentialAsTime("expires_at")
					}
				}
			}
		} else {
			// 锁获取失败（被其他 worker 持有），等待后重试读取缓存
			time.Sleep(kiroLockWaitTime)
			if token, err := p.tokenCache.GetAccessToken(ctx, cacheKey); err == nil && strings.TrimSpace(token) != "" {
				slog.Debug("kiro_token_cache_hit_after_wait", "account_id", account.ID)
				return token, nil
			}
		}
	}

	accessToken := account.GetCredential("access_token")
	if strings.TrimSpace(accessToken) == "" {
		return "", errors.New("access_token not found in credentials")
	}

	// 3. 存入缓存
	if p.tokenCache != nil {
		latestAccount, isStale := CheckTokenVersion(ctx, account, p.accountRepo)
		if isStale && latestAccount != nil {
			slog.Debug("kiro_token_version_stale_use_latest", "account_id", account.ID)
			accessToken = latestAccount.GetCredential("access_token")
			if strings.TrimSpace(accessToken) == "" {
				return "", errors.New("access_token not found after version check")
			}
		} else {
			ttl := 30 * time.Minute
			if refreshFailed {
				ttl = time.Minute
				slog.Debug("kiro_token_cache_short_ttl", "account_id", account.ID, "reason", "refresh_failed")
			} else if expiresAt != nil {
				until := time.Until(*expiresAt)
				switch {
				case until > kiroTokenCacheSkew:
					ttl = until - kiroTokenCacheSkew
				case until > 0:
					ttl = until
				default:
					ttl = time.Minute
				}
			}
			if err := p.tokenCache.SetAccessToken(ctx, cacheKey, accessToken, ttl); err != nil {
				slog.Warn("kiro_token_cache_set_failed", "account_id", account.ID, "error", err)
			}
		}
	}

	return accessToken, nil
}
