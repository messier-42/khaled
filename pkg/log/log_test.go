package log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	t.Parallel()

	accepted := map[string]Format{
		"json": FormatJSON,
		"text": FormatText,
	}
	for input, want := range accepted {
		got, err := ParseFormat(input)
		if err != nil {
			t.Errorf("ParseFormat(%q) returned error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", input, got, want)
		}
	}

	rejected := []string{"", "JSON", "Json", "TEXT", "Text", "yaml", " json", "json ", "log", "pretty"}
	for _, input := range rejected {
		if _, err := ParseFormat(input); err == nil {
			t.Errorf("ParseFormat(%q) accepted, want error", input)
		}
	}
}

func TestNewJSONFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelInfo})
	logger.Info("hello", "k", "v")

	line := strings.TrimRight(buf.String(), "\n")
	if line == "" {
		t.Fatal("expected one log line, got empty output")
	}
	if strings.Contains(line, "\n") {
		t.Errorf("JSON output must be single-line per record: %q", buf.String())
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v; raw=%q", err, line)
	}
	if rec["msg"] != "hello" {
		t.Errorf("rec[msg] = %v, want %q", rec["msg"], "hello")
	}
	if rec["level"] != "INFO" {
		t.Errorf("rec[level] = %v, want %q", rec["level"], "INFO")
	}
	if rec["k"] != "v" {
		t.Errorf("rec[k] = %v, want %q", rec["k"], "v")
	}
}

func TestNewTextFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, Config{Format: FormatText, Severity: slog.LevelInfo})
	logger.Info("hello", "k", "v")

	out := buf.String()
	if out == "" {
		t.Fatal("expected output, got none")
	}
	// Text handler output is not JSON.
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimRight(out, "\n")), &rec); err == nil {
		t.Errorf("text format should not be valid JSON: %q", out)
	}
	if !strings.Contains(out, "msg=hello") {
		t.Errorf("text output missing msg=hello: %q", out)
	}
	if !strings.Contains(out, "k=v") {
		t.Errorf("text output missing k=v: %q", out)
	}
}

func TestNewSeverityFilters(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelError})
	logger.Info("suppress me")
	logger.Warn("suppress me too")
	logger.Error("let me through")

	out := buf.String()
	if strings.Contains(out, "suppress") {
		t.Errorf("severity=error should suppress info/warn, got: %q", out)
	}
	if !strings.Contains(out, "let me through") {
		t.Errorf("severity=error should emit error records, got: %q", out)
	}
}
