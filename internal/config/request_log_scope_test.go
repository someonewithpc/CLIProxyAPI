package config

import "testing"

func TestRequestLogScopeKeysParse(t *testing.T) {
	cases := map[string]string{
		"flat": `
request-log: true
request-log-only-header: X-Sashiko-Review
request-log-dir: /var/log/sashiko
`,
		"nested": `
observability:
  logs:
    request-log: true
    request-log-only-header: X-Sashiko-Review
    request-log-dir: /var/log/sashiko
`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.RequestLog || cfg.RequestLogOnlyHeader != "X-Sashiko-Review" || cfg.RequestLogDir != "/var/log/sashiko" {
				t.Fatalf("got request-log=%v only-header=%q dir=%q", cfg.RequestLog, cfg.RequestLogOnlyHeader, cfg.RequestLogDir)
			}
		})
	}

	cfg, err := ParseConfigBytes([]byte("request-log: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestLogOnlyHeader != "" || cfg.RequestLogDir != "" {
		t.Fatalf("defaults must be empty, got %q %q", cfg.RequestLogOnlyHeader, cfg.RequestLogDir)
	}
}

func TestRequestLogScopeKeysMigrateToNestedLayout(t *testing.T) {
	raw := []byte("request-log: true\nrequest-log-only-header: X-Review\nrequest-log-dir: review-logs\n")
	migrated, _, err := NormalizeConfigLayout(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateV8Config(migrated); err != nil {
		t.Fatalf("migrated config is not v8: %v\n%s", err, migrated)
	}
	cfg, err := ParseConfigBytes(migrated)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestLogOnlyHeader != "X-Review" || cfg.RequestLogDir != "review-logs" {
		t.Fatalf("migration lost the keys:\n%s", migrated)
	}
}
