package output

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"clean string", "hello world", "hello world"},
		{"ANSI clear screen", "before\x1b[2Jafter", "beforeafter"},
		{"ANSI color", "\x1b[31mred\x1b[0m", "red"},
		{"newline removed", "line1\nline2", "line1line2"},
		{"carriage return removed", "line1\rline2", "line1line2"},
		{"null byte removed", "abc\x00def", "abcdef"},
		{"tab removed", "col1\tcol2", "col1col2"},
		{"DEL removed", "abc\x7fdef", "abcdef"},
		{"UTF-8 preserved", "héllo wörld", "héllo wörld"},
		{"emoji preserved", "hello 🌍", "hello 🌍"},
		{"empty string", "", ""},
		{"only control chars", "\x1b[2J\x00\n\r", ""},
		{"mixed", "user: \x1b[31mEvil\x1b[0m\nMarcus", "user: EvilMarcus"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitize(tc.input)
			if got != tc.want {
				t.Errorf("sanitize(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeArgs(t *testing.T) {
	args := []any{"user\x1b[31m", 42, true, "clean"}
	result := sanitizeArgs(args)
	if result[0] != "user" {
		t.Errorf("string arg not sanitized: got %q", result[0])
	}
	if result[1] != 42 {
		t.Errorf("int arg modified: got %v", result[1])
	}
	if result[2] != true {
		t.Errorf("bool arg modified: got %v", result[2])
	}
	if result[3] != "clean" {
		t.Errorf("clean string modified: got %q", result[3])
	}
}

func TestFprintf(t *testing.T) {
	var buf bytes.Buffer
	Fprintf(&buf, "user: %s count: %d\n", "evil\x1b[2J", 5)
	got := buf.String()
	want := fmt.Sprintf("user: %s count: %d\n", "evil", 5)
	if got != want {
		t.Errorf("Fprintf output = %q, want %q", got, want)
	}
}
