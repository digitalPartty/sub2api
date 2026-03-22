package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/kiro"
)

type KiroOAuthService struct {
	proxyRepo ProxyRepository
}

func NewKiroOAuthService(proxyRepo ProxyRepository) *KiroOAuthService {
	return &KiroOAuthService{
		proxyRepo: proxyRepo,
	}
}

// KiroTokenInfo token 信息
type KiroTokenInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope,omitempty"`
}

// RefreshAccountToken 刷新 Kiro OAuth Token
// 支持两种认证方式:
// 1. Social 认证 (Builder ID): 使用 refresh_token
// 2. IdC 认证: 使用 refresh_token + client_id + client_secret
func (s *KiroOAuthService) RefreshAccountToken(ctx context.Context, account *Account) (*KiroTokenInfo, error) {
	if account == nil {
		return nil, fmt.Errorf("account is nil")
	}
	if account.Platform != PlatformKiro {
		return nil, fmt.Errorf("not a kiro account")
	}
	if account.Type != AccountTypeOAuth {
		return nil, fmt.Errorf("not an oauth account")
	}

	refreshToken := account.GetCredential("refresh_token")
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("refresh_token not found in credentials")
	}

	// 检查 refreshToken 长度 (kiro.rs 要求 >= 100 字符)
	if len(refreshToken) < 100 {
		return nil, fmt.Errorf("refresh_token too short (length: %d, required: >= 100)", len(refreshToken))
	}

	// 获取代理配置
	var proxyURL string
	if account.ProxyID != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *account.ProxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// 创建 HTTP 客户端
	client, err := kiro.NewClient(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("create kiro client failed: %w", err)
	}

	// 获取 base_url (默认使用 Kiro 官方 API)
	baseURL := account.GetCredential("base_url")
	if strings.TrimSpace(baseURL) == "" {
		baseURL = kiro.DefaultBaseURL
	}

	// 判断认证方式: 检查是否有 client_id 和 client_secret
	clientID := account.GetCredential("client_id")
	clientSecret := account.GetCredential("client_secret")

	var tokenResp *kiro.TokenResponse
	if strings.TrimSpace(clientID) != "" && strings.TrimSpace(clientSecret) != "" {
		// IdC 认证方式
		tokenResp, err = s.refreshTokenIdC(ctx, client, baseURL, refreshToken, clientID, clientSecret)
	} else {
		// Social 认证方式
		tokenResp, err = s.refreshTokenSocial(ctx, client, baseURL, refreshToken)
	}

	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// 计算过期时间 (减去 5 分钟安全窗口)
	expiresAt := time.Now().Unix() + tokenResp.ExpiresIn - 300

	return &KiroTokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    expiresAt,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
	}, nil
}

// refreshTokenSocial 使用 Social 认证方式刷新 Token
func (s *KiroOAuthService) refreshTokenSocial(ctx context.Context, client *http.Client, baseURL, refreshToken string) (*kiro.TokenResponse, error) {
	tokenURL := strings.TrimSuffix(baseURL, "/") + "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed (status: %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp kiro.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse response failed: %w", err)
	}

	return &tokenResp, nil
}

// refreshTokenIdC 使用 IdC 认证方式刷新 Token
func (s *KiroOAuthService) refreshTokenIdC(ctx context.Context, client *http.Client, baseURL, refreshToken, clientID, clientSecret string) (*kiro.TokenResponse, error) {
	tokenURL := strings.TrimSuffix(baseURL, "/") + "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed (status: %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp kiro.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse response failed: %w", err)
	}

	return &tokenResp, nil
}

// KiroTokenCacheKey 生成 Kiro Token 缓存键
func KiroTokenCacheKey(account *Account) string {
	return "kiro:token:" + strconv.FormatInt(account.ID, 10)
}
