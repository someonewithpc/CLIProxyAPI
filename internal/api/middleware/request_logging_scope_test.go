package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
)

type scopedRequestResult struct {
	fullLog       bool
	deferredAPI   bool
	capturedAPI   bool
	redactHeaders bool
}

func runScopedLoggingRequest(t *testing.T, logger *logging.FileRequestLogger, headers http.Header) scopedRequestResult {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{SDKConfig: config.SDKConfig{RequestLog: true}}
	var result scopedRequestResult

	router := gin.New()
	router.Use(RequestLoggingMiddleware(logger))
	router.POST("/v1/messages", func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		c.Header("Set-Cookie", "session=upstream-cookie-value")
		executorCtx := context.WithValue(context.Background(), "gin", c)
		helps.RecordAPIRequest(executorCtx, cfg, helps.UpstreamRequestLog{
			URL:    "https://api.example.com/v1/messages",
			Method: http.MethodPost,
			Headers: http.Header{
				"Content-Type":  []string{"application/json"},
				"Authorization": []string{"Bearer sk-ant-oat01-upstream-secret-token"},
				"X-Api-Key":     []string{"sk-ant-api03-upstream-secret-key"},
			},
			Body: []byte(`{"model":"claude"}`),
		})
		helps.RecordAPIResponseMetadata(executorCtx, cfg, http.StatusOK, http.Header{"Set-Cookie": []string{"cf=upstream-set-cookie"}})
		helps.AppendAPIResponseChunk(executorCtx, cfg, []byte("event: message_delta\ndata: {\"usage\":{\"output_tokens\":42}}"))
		_, _ = c.Writer.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n"))
		if flusher, ok := c.Writer.(http.Flusher); ok {
			flusher.Flush()
		}
		result.fullLog = logging.FullRequestLogEnabled(c)
		result.redactHeaders = logging.RedactRequestLogHeaders(c)
		_, result.deferredAPI = c.Get(logging.DeferredAPIRequestContextKey)
		_, captured := c.Get("API_REQUEST")
		_, source := c.Get(logging.APIRequestSourceContextKey)
		result.capturedAPI = captured || source
	})

	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"claude","stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusOK)
	}
	return result
}

func findRequestLogs(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	errWalk := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "v1-messages-") && strings.HasSuffix(entry.Name(), ".log") {
			found = append(found, path)
		}
		return nil
	})
	if errWalk != nil {
		t.Fatalf("walk %s: %v", root, errWalk)
	}
	return found
}

func TestRequestLoggingMiddlewareHeaderGateLogsTaggedStreamToRequestLogDir(t *testing.T) {
	logsDir := t.TempDir()
	requestLogDir := t.TempDir()
	logger := logging.NewFileRequestLogger(true, logsDir, "", 10)
	logger.SetRequestLogScope("x-sashiko-review", requestLogDir)

	result := runScopedLoggingRequest(t, logger, http.Header{
		"X-Sashiko-Review": []string{"linux/drm-fix"},
		"Authorization":    []string{"Bearer client-secret-token-value"},
		"X-Api-Key":        []string{"client-api-key-value"},
		"Cookie":           []string{"session=client-cookie-value"},
	})
	if !result.fullLog || !result.redactHeaders || !result.capturedAPI || result.deferredAPI {
		t.Fatalf("tagged request should be fully logged with redaction: %+v", result)
	}

	if logs := findRequestLogs(t, logsDir); len(logs) != 0 {
		t.Fatalf("tagged request logged into the logs dir: %v", logs)
	}
	logs := findRequestLogs(t, requestLogDir)
	if len(logs) != 1 {
		t.Fatalf("want one log under request-log-dir, got %v", logs)
	}
	if got := filepath.Base(filepath.Dir(logs[0])); got != "linux-drm-fix" {
		t.Fatalf("log subdirectory = %q, want linux-drm-fix", got)
	}
	content, errRead := os.ReadFile(logs[0])
	if errRead != nil {
		t.Fatal(errRead)
	}
	text := string(content)
	for _, want := range []string{"=== API REQUEST 1 ===", "=== API RESPONSE 1 ===", `"output_tokens":42`, "Bearer [REDACTED]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("log missing %q:\n%s", want, text)
		}
	}
	for _, secret := range []string{"client-secret-token", "client-api-key", "client-cookie", "upstream-secret", "upstream-cookie", "upstream-set-cookie", "-value"} {
		if strings.Contains(text, secret) {
			t.Fatalf("log leaks %q:\n%s", secret, text)
		}
	}
}

func TestRequestLoggingMiddlewareHeaderGateSkipsUntaggedRequests(t *testing.T) {
	for name, headers := range map[string]http.Header{
		"missing": {},
		"empty":   {"X-Sashiko-Review": []string{"   "}},
	} {
		t.Run(name, func(t *testing.T) {
			logsDir := t.TempDir()
			requestLogDir := t.TempDir()
			logger := logging.NewFileRequestLogger(true, logsDir, "", 10)
			logger.SetRequestLogScope("X-Sashiko-Review", requestLogDir)

			result := runScopedLoggingRequest(t, logger, headers)
			if result.fullLog || result.redactHeaders || result.capturedAPI || !result.deferredAPI {
				t.Fatalf("untagged request should behave as request-log off: %+v", result)
			}
			if logs := append(findRequestLogs(t, logsDir), findRequestLogs(t, requestLogDir)...); len(logs) != 0 {
				t.Fatalf("untagged successful request was logged: %v", logs)
			}
		})
	}
}

func TestRequestLoggingMiddlewareWithoutHeaderGateLogsEverything(t *testing.T) {
	logsDir := t.TempDir()
	logger := logging.NewFileRequestLogger(true, logsDir, "", 10)
	logger.SetRequestLogScope("", t.TempDir())

	result := runScopedLoggingRequest(t, logger, http.Header{"Authorization": []string{"Bearer client-secret-token-value"}})
	if !result.fullLog || result.redactHeaders || !result.capturedAPI {
		t.Fatalf("unscoped request should be fully logged: %+v", result)
	}
	logs := findRequestLogs(t, logsDir)
	if len(logs) != 1 || filepath.Dir(logs[0]) != logsDir {
		t.Fatalf("want one log in the logs dir, got %v", logs)
	}
}
