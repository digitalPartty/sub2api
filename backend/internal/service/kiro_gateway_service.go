package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/kiro"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	kiroStickySessionTTL  = time.Hour
	kiroMaxRetries        = 3
	kiroRetryBaseDelay    = 1 * time.Second
	kiroRetryMaxDelay     = 16 * time.Second
	kiroDefaultMaxLineSize = 500 * 1024 * 1024
)

// KiroGatewayService Kiro 网关服务
type KiroGatewayService struct {
	tokenProvider  *KiroTokenProvider
	httpUpstream   HTTPUpstream
	accountRepo    AccountRepository
	settingService *SettingService
}

func NewKiroGatewayService(
	tokenProvider *KiroTokenProvider,
	httpUpstream HTTPUpstream,
	accountRepo AccountRepository,
	settingService *SettingService,
) *KiroGatewayService {
	return &KiroGatewayService{
		tokenProvider:  tokenProvider,
		httpUpstream:   httpUpstream,
		accountRepo:    accountRepo,
		settingService: settingService,
	}
}

// HandleMessages 处理 /kiro/v1/messages 请求
func (s *KiroGatewayService) HandleMessages(c *gin.Context, account *Account, requestBody []byte) error {
	ctx := c.Request.Context()

	// 获取 access token
	accessToken, err := s.tokenProvider.GetAccessToken(ctx, account)
	if err != nil {
		return fmt.Errorf("get access token failed: %w", err)
	}

	// 获取 base_url
	baseURL := account.GetCredential("base_url")
	if strings.TrimSpace(baseURL) == "" {
		baseURL = kiro.DefaultBaseURL
	}

	// 构建上游 URL
	upstreamURL := strings.TrimSuffix(baseURL, "/") + "/v1/messages"

	// 解析请求体获取 stream 参数
	isStream := gjson.GetBytes(requestBody, "stream").Bool()

	// 重试循环
	var lastErr error
	for attempt := 0; attempt < kiroMaxRetries; attempt++ {
		if attempt > 0 {
			delay := kiroRetryBaseDelay * time.Duration(1<<uint(attempt-1))
			if delay > kiroRetryMaxDelay {
				delay = kiroRetryMaxDelay
			}
			slog.Debug("kiro_retry_delay", "account_id", account.ID, "attempt", attempt, "delay", delay)
			time.Sleep(delay)
		}

		// 创建上游请求
		req, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, bytes.NewReader(requestBody))
		if err != nil {
			lastErr = fmt.Errorf("create request failed: %w", err)
			continue
		}

		// 设置请求头
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("anthropic-version", "2023-06-01")

		// 复制客户端请求头
		for key, values := range c.Request.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-") || key == "User-Agent" {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}

		// 发送请求
		resp, err := s.httpUpstream.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			slog.Warn("kiro_request_failed", "account_id", account.ID, "attempt", attempt, "error", err)
			continue
		}

		// 处理响应
		if resp.StatusCode == http.StatusOK {
			if isStream {
				return s.handleStreamResponse(c, resp)
			}
			return s.handleNonStreamResponse(c, resp)
		}

		// 读取错误响应
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		slog.Warn("kiro_upstream_error",
			"account_id", account.ID,
			"status", resp.StatusCode,
			"body", string(respBody),
			"attempt", attempt)

		// 错误处理策略
		switch resp.StatusCode {
		case http.StatusBadRequest:
			// 400: 直接返回,不重试
			c.Data(resp.StatusCode, "application/json", respBody)
			return nil

		case http.StatusUnauthorized, http.StatusForbidden:
			// 401/403: Token 失效,可以重试
			lastErr = fmt.Errorf("authentication failed: status=%d", resp.StatusCode)
			continue

		case http.StatusPaymentRequired:
			// 402: 配额耗尽,禁用账号
			if err := s.disableAccount(ctx, account); err != nil {
				slog.Error("kiro_disable_account_failed", "account_id", account.ID, "error", err)
			}
			c.Data(resp.StatusCode, "application/json", respBody)
			return nil

		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			// 429/503: 限流,重试
			lastErr = fmt.Errorf("rate limited: status=%d", resp.StatusCode)
			continue

		default:
			// 其他错误: 返回给客户端
			c.Data(resp.StatusCode, "application/json", respBody)
			return nil
		}
	}

	// 所有重试都失败
	if lastErr != nil {
		return lastErr
	}
	return errors.New("all retries failed")
}

// handleStreamResponse 处理流式响应
func (s *KiroGatewayService) handleStreamResponse(c *gin.Context, resp *http.Response) error {
	defer resp.Body.Close()

	// 设置响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	// 复制上游响应头
	for key, values := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-") {
			for _, value := range values {
				c.Header(key, value)
			}
		}
	}

	c.Status(http.StatusOK)

	// 流式转发
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return errors.New("streaming not supported")
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), kiroDefaultMaxLineSize)

	for scanner.Scan() {
		line := scanner.Text()
		if _, err := c.Writer.Write([]byte(line + "\n")); err != nil {
			return fmt.Errorf("write response failed: %w", err)
		}
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read stream failed: %w", err)
	}

	return nil
}

// handleNonStreamResponse 处理非流式响应
func (s *KiroGatewayService) handleNonStreamResponse(c *gin.Context, resp *http.Response) error {
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response failed: %w", err)
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	return nil
}

// HandleCountTokens 处理 /kiro/v1/messages/count_tokens 请求
func (s *KiroGatewayService) HandleCountTokens(c *gin.Context, account *Account, requestBody []byte) error {
	ctx := c.Request.Context()

	// 获取 access token
	accessToken, err := s.tokenProvider.GetAccessToken(ctx, account)
	if err != nil {
		return fmt.Errorf("get access token failed: %w", err)
	}

	// 获取 base_url
	baseURL := account.GetCredential("base_url")
	if strings.TrimSpace(baseURL) == "" {
		baseURL = kiro.DefaultBaseURL
	}

	// 构建上游 URL
	upstreamURL := strings.TrimSuffix(baseURL, "/") + "/v1/messages/count_tokens"

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("create request failed: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-version", "2023-06-01")

	// 发送请求
	resp, err := s.httpUpstream.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response failed: %w", err)
	}

	// 返回响应
	c.Data(resp.StatusCode, "application/json", body)
	return nil
}

// HandleModels 处理 /kiro/v1/models 请求
func (s *KiroGatewayService) HandleModels(c *gin.Context) error {
	// 返回 Kiro 支持的模型列表
	models := []map[string]interface{}{
		{
			"id":         "claude-sonnet-4-5-20250929",
			"type":       "model",
			"display_name": "Claude Sonnet 4.5",
			"created_at": "2025-09-29T00:00:00Z",
		},
		{
			"id":         "claude-opus-4-5-20251101",
			"type":       "model",
			"display_name": "Claude Opus 4.5",
			"created_at": "2025-11-01T00:00:00Z",
		},
		{
			"id":         "claude-haiku-4-5-20251001",
			"type":       "model",
			"display_name": "Claude Haiku 4.5",
			"created_at": "2025-10-01T00:00:00Z",
		},
	}

	response := map[string]interface{}{
		"data":    models,
		"has_more": false,
		"first_id": "claude-sonnet-4-5-20250929",
		"last_id":  "claude-haiku-4-5-20251001",
	}

	c.JSON(http.StatusOK, response)
	return nil
}

// disableAccount 禁用账号
func (s *KiroGatewayService) disableAccount(ctx context.Context, account *Account) error {
	account.Status = StatusDisabled
	if err := s.accountRepo.Update(ctx, account); err != nil {
		return fmt.Errorf("update account failed: %w", err)
	}
	slog.Info("kiro_account_disabled", "account_id", account.ID, "reason", "quota_exhausted")
	return nil
}

// ExtractUsageFromResponse 从响应中提取 usage 信息
func ExtractKiroUsageFromResponse(body []byte) (inputTokens, outputTokens, cacheReadTokens int64) {
	usage := gjson.GetBytes(body, "usage")
	if !usage.Exists() {
		return 0, 0, 0
	}

	inputTokens = usage.Get("input_tokens").Int()
	outputTokens = usage.Get("output_tokens").Int()

	// Kiro 可能支持缓存
	cacheCreationTokens := usage.Get("cache_creation_input_tokens").Int()
	cacheReadTokens = usage.Get("cache_read_input_tokens").Int()

	// 如果有缓存创建,计入 input_tokens
	if cacheCreationTokens > 0 {
		inputTokens += cacheCreationTokens
	}

	return inputTokens, outputTokens, cacheReadTokens
}
