package logging

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
)

const (
	unnamedRequestLogDir     = "unnamed"
	maxRequestLogDirNameSize = 64
)

type requestLogScope struct {
	header string
	dir    string
}

// RequestScopedLogger returns the logger that should record one request.
type RequestScopedLogger interface {
	ForRequest(headers http.Header) RequestLogger
}

// SetRequestLogScope limits full request logging to requests that carry a non-empty
// header named headerName. When dir is non-empty, those logs go to
// <dir>/<sanitized header value>/. A relative dir resolves against the config directory.
// An empty headerName logs every request when logging is enabled.
func (l *FileRequestLogger) SetRequestLogScope(headerName, dir string) {
	if l == nil {
		return
	}
	headerName = strings.TrimSpace(headerName)
	dir = strings.TrimSpace(dir)
	if dir != "" && !filepath.IsAbs(dir) && l.configDir != "" {
		dir = filepath.Join(l.configDir, dir)
	}
	l.scope.Store(&requestLogScope{header: headerName, dir: dir})
}

// ForRequest returns a logger for one request. Without a request-log-only-header it
// returns l. Otherwise a request without the header gets a logger with full logging off,
// so only errors are logged, and a request with it gets a logger writing to its
// request-log-dir subdirectory with credential headers redacted.
func (l *FileRequestLogger) ForRequest(headers http.Header) RequestLogger {
	if l == nil || !l.enabled {
		return l
	}
	scope := l.scope.Load()
	if scope == nil || scope.header == "" {
		return l
	}
	value := strings.TrimSpace(headers.Get(scope.header))
	scoped := &FileRequestLogger{
		enabled:           value != "",
		logsDir:           l.logsDir,
		configDir:         l.configDir,
		errorLogsMaxFiles: l.errorLogsMaxFiles,
		homeEnabled:       l.homeEnabled,
		redactHeaders:     value != "",
	}
	if value != "" && scope.dir != "" {
		scoped.logsDir = filepath.Join(scope.dir, SanitizeRequestLogDirName(value))
	}
	return scoped
}

// RedactsHeaders reports whether this logger fully redacts credential headers.
func (l *FileRequestLogger) RedactsHeaders() bool {
	return l != nil && l.redactHeaders
}

// SanitizeRequestLogDirName turns a header value into one safe path component.
// It keeps ASCII letters, digits, '-', '_' and single '.', drops leading and
// trailing separators, caps the length, and falls back to "unnamed".
func SanitizeRequestLogDirName(value string) string {
	var b strings.Builder
	lastSep := true
	for _, r := range strings.TrimSpace(value) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
			lastSep = false
		case r == '.' || r == '-':
			if !lastSep {
				b.WriteRune(r)
			}
			lastSep = true
		default:
			if !lastSep {
				b.WriteRune('-')
			}
			lastSep = true
		}
		if b.Len() >= maxRequestLogDirNameSize {
			break
		}
	}
	name := b.String()
	if len(name) > maxRequestLogDirNameSize {
		name = name[:maxRequestLogDirNameSize]
	}
	name = strings.Trim(name, ".-")
	if name == "" {
		return unnamedRequestLogDir
	}
	return name
}

// FullRequestLogEnabled reports whether the request in c was selected for full logging.
// Requests the logging middleware did not mark keep the global request-log setting.
func FullRequestLogEnabled(c *gin.Context) bool {
	if c == nil {
		return true
	}
	value, exists := c.Get(RequestLogFullContextKey)
	if !exists {
		return true
	}
	enabled, ok := value.(bool)
	return !ok || enabled
}

// RedactRequestLogHeaders reports whether request logs for c must fully redact
// credential headers.
func RedactRequestLogHeaders(c *gin.Context) bool {
	if c == nil {
		return false
	}
	value, exists := c.Get(RequestLogRedactHeadersContextKey)
	if !exists {
		return false
	}
	redact, _ := value.(bool)
	return redact
}

func redactHeadersIf(redact bool, headers map[string][]string) map[string][]string {
	if !redact {
		return headers
	}
	return util.RedactSensitiveHeaders(headers)
}
