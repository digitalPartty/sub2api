package admin

import (
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

type KiroOAuthHandler struct {
	kiroOAuthService *service.KiroOAuthService
}

func NewKiroOAuthHandler(kiroOAuthService *service.KiroOAuthService) *KiroOAuthHandler {
	return &KiroOAuthHandler{kiroOAuthService: kiroOAuthService}
}

type KiroGenerateAuthURLRequest struct {
	ProxyID *int64 `json:"proxy_id"`
	// AuthType OAuth 认证类型: "social" (Builder ID) 或 "idc" (Enterprise)
	AuthType string `json:"auth_type"`
}

// GenerateAuthURL generates Kiro OAuth authorization URL.
// POST /api/v1/admin/kiro/oauth/auth-url
func (h *KiroOAuthHandler) GenerateAuthURL(c *gin.Context) {
	var req KiroGenerateAuthURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	// 默认使用 social 认证
	authType := strings.TrimSpace(req.AuthType)
	if authType == "" {
		authType = "social"
	}
	if authType != "social" && authType != "idc" {
		response.BadRequest(c, "Invalid auth_type: must be 'social' or 'idc'")
		return
	}

	// 构建回调 URL
	redirectURI := deriveKiroRedirectURI(c)

	// 生成授权 URL (简化版,直接返回配置的 URL)
	// 实际实现中可能需要生成 state 和 code_verifier
	result := map[string]interface{}{
		"auth_url":     h.getAuthURL(authType),
		"redirect_uri": redirectURI,
		"auth_type":    authType,
	}

	response.Success(c, result)
}

type KiroExchangeCodeRequest struct {
	Code     string `json:"code" binding:"required"`
	ProxyID  *int64 `json:"proxy_id"`
	AuthType string `json:"auth_type"`
}

// ExchangeCode exchanges authorization code for tokens.
// POST /api/v1/admin/kiro/oauth/exchange-code
func (h *KiroOAuthHandler) ExchangeCode(c *gin.Context) {
	var req KiroExchangeCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	// 默认使用 social 认证
	authType := strings.TrimSpace(req.AuthType)
	if authType == "" {
		authType = "social"
	}
	if authType != "social" && authType != "idc" {
		response.BadRequest(c, "Invalid auth_type: must be 'social' or 'idc'")
		return
	}

	// 注意: 这里简化了实现,实际应该通过 KiroOAuthService 交换 token
	// 由于 kiro.rs 的 OAuth 流程需要 code_verifier,这里需要存储 session
	response.BadRequest(c, "Kiro OAuth exchange not fully implemented yet. Please use manual token configuration.")
}

func (h *KiroOAuthHandler) getAuthURL(authType string) string {
	// 这里应该从配置中读取,暂时返回占位符
	if authType == "idc" {
		return "https://api.kiro.so/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID"
	}
	return "https://api.kiro.so/oauth/authorize?response_type=code"
}

func deriveKiroRedirectURI(c *gin.Context) string {
	origin := strings.TrimSpace(c.GetHeader("Origin"))
	if origin != "" {
		return strings.TrimRight(origin, "/") + "/auth/kiro/callback"
	}

	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if xfProto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); xfProto != "" {
		scheme = strings.TrimSpace(strings.Split(xfProto, ",")[0])
	}

	host := strings.TrimSpace(c.Request.Host)
	if xfHost := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); xfHost != "" {
		host = strings.TrimSpace(strings.Split(xfHost, ",")[0])
	}

	return fmt.Sprintf("%s://%s/auth/kiro/callback", scheme, host)
}
