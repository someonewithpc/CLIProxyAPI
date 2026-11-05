package logging

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizeRequestLogDirName(t *testing.T) {
	cases := map[string]string{
		"linux-drm":                    "linux-drm",
		"  review_42  ":                "review_42",
		"../../etc/passwd":             "etc-passwd",
		"..":                           "unnamed",
		".":                            "unnamed",
		".hidden":                      "hidden",
		"a/b\\c":                       "a-b-c",
		"a..b":                         "a.b",
		"name.":                        "name",
		"":                             "unnamed",
		"///":                          "unnamed",
		"ünïcode":                      "n-code",
		"x" + strings.Repeat("y", 100): "x" + strings.Repeat("y", 63),
	}
	for input, want := range cases {
		got := SanitizeRequestLogDirName(input)
		if got != want {
			t.Errorf("SanitizeRequestLogDirName(%q) = %q, want %q", input, got, want)
		}
		if strings.ContainsAny(got, `/\`) || strings.HasPrefix(got, ".") || strings.Contains(got, "..") || len(got) > maxRequestLogDirNameSize {
			t.Errorf("SanitizeRequestLogDirName(%q) = %q is not a safe path component", input, got)
		}
	}
}

func TestFileRequestLoggerForRequestHeaderGate(t *testing.T) {
	logsDir := t.TempDir()
	requestLogDir := t.TempDir()
	logger := NewFileRequestLogger(true, logsDir, "", 10)

	if got := logger.ForRequest(http.Header{}); got != RequestLogger(logger) {
		t.Fatal("without a scope ForRequest must return the logger itself")
	}

	logger.SetRequestLogScope("x-sashiko-review", requestLogDir)
	tagged := http.Header{}
	tagged.Set("X-SASHIKO-REVIEW", "drm/amd")
	scoped, ok := logger.ForRequest(tagged).(*FileRequestLogger)
	if !ok || !scoped.IsEnabled() || !scoped.RedactsHeaders() {
		t.Fatalf("tagged request must get an enabled redacting logger, got %#v", scoped)
	}
	if want := filepath.Join(requestLogDir, "drm-amd"); scoped.logsDir != want {
		t.Fatalf("scoped logs dir = %q, want %q", scoped.logsDir, want)
	}

	for name, headers := range map[string]http.Header{
		"missing": {},
		"empty":   {"X-Sashiko-Review": []string{""}},
		"blank":   {"X-Sashiko-Review": []string{"  "}},
	} {
		untagged := logger.ForRequest(headers).(*FileRequestLogger)
		if untagged.IsEnabled() || untagged.RedactsHeaders() || untagged.logsDir != logsDir {
			t.Fatalf("%s header: want a disabled logger on the logs dir, got %#v", name, untagged)
		}
	}

	logger.SetRequestLogScope("X-Sashiko-Review", "")
	if scoped := logger.ForRequest(tagged).(*FileRequestLogger); scoped.logsDir != logsDir || !scoped.IsEnabled() {
		t.Fatalf("without request-log-dir tagged logs stay in the logs dir, got %q", scoped.logsDir)
	}

	logger.SetEnabled(false)
	if got := logger.ForRequest(tagged); got != RequestLogger(logger) || got.IsEnabled() {
		t.Fatal("with request-log off ForRequest must return the disabled logger")
	}
}

func TestFileRequestLoggerRequestLogDirResolvesAgainstConfigDir(t *testing.T) {
	configDir := t.TempDir()
	logger := NewFileRequestLogger(true, "logs", configDir, 10)
	logger.SetRequestLogScope("X-Review", "review-logs")
	scoped := logger.ForRequest(http.Header{"X-Review": []string{"a"}}).(*FileRequestLogger)
	if want := filepath.Join(configDir, "review-logs", "a"); scoped.logsDir != want {
		t.Fatalf("scoped logs dir = %q, want %q", scoped.logsDir, want)
	}
}

func TestHeaderGatedLogsSurviveLogDirCleaner(t *testing.T) {
	logsDir := t.TempDir()
	logger := NewFileRequestLogger(true, logsDir, "", 10)
	logger.SetRequestLogScope("X-Review", filepath.Join(logsDir, "reviews"))
	scoped := logger.ForRequest(http.Header{"X-Review": []string{"one"}}).(*FileRequestLogger)
	headers := map[string][]string{"Authorization": {"Bearer secret-token-value"}, "Cookie": {"a=b"}}
	if err := scoped.LogRequest("/v1/messages", http.MethodPost, headers, []byte("{}"), http.StatusOK, map[string][]string{"Set-Cookie": {"c=d"}}, []byte("ok"), nil, nil, nil, nil, nil, "req-1", time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(logsDir, "reviews", "one"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("want one gated log, got %v (%v)", entries, err)
	}
	path := filepath.Join(logsDir, "reviews", "one", entries[0].Name())
	content, _ := os.ReadFile(path)
	if strings.Contains(string(content), "secret-token") || strings.Contains(string(content), "a=b") || strings.Contains(string(content), "c=d") {
		t.Fatalf("gated log leaks credentials:\n%s", content)
	}

	if err = os.WriteFile(filepath.Join(logsDir, "main.log"), make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = enforceLogDirSizeLimit(logsDir, 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatalf("log dir cleaner removed the gated log: %v", err)
	}
}
