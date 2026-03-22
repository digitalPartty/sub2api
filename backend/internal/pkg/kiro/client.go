package kiro

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

const (
	// DefaultBaseURL Kiro 官方 API 地址
	DefaultBaseURL = "https://api.kiro.so"

	// DefaultTimeout 默认超时时间
	DefaultTimeout = 120 * time.Second
)

// TokenResponse OAuth Token 响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope,omitempty"`
}

// NewClient 创建 HTTP 客户端
func NewClient(proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// 配置代理
	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURLParsed)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}, nil
}
