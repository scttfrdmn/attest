// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package output provides terminal-safe print functions.
// All string arguments are sanitized to strip ANSI escape sequences and control
// characters before being written to stdout/stderr. This prevents terminal injection
// attacks where user-controlled or externally-sourced strings embed escape codes
// (e.g., ESC[2J to clear the screen, ESC[31m to change text color).
//
// Usage: replace fmt.Printf/fmt.Println calls that receive user or external data
// with output.Printf/output.Println. Calls with only hardcoded format strings and
// integers/booleans are safe to leave as fmt.Printf.
//
// This package is the single enforcement point — fixing it here protects every
// call site rather than requiring per-site manual application.
package output

import (
	"fmt"
	"io"
	"os"
	"regexp"
)

// ansiRE matches ANSI CSI escape sequences: ESC [ <params> <letter>
// e.g., ESC[31m (red), ESC[2J (clear screen), ESC[0m (reset)
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// sanitize strips ANSI CSI escape sequences and control characters from s.
// Step 1: remove full ANSI sequences (ESC[...letter) so `[31m` isn't left behind.
// Step 2: remove remaining control characters (< 0x20 and DEL 0x7F).
// Safe for UTF-8: multi-byte sequences start at 0xC0+ and are preserved.
func sanitize(s string) string {
	// Fast path: skip if no ESC or control characters present.
	hasControl := false
	for _, r := range s {
		if r < 32 || r == 127 {
			hasControl = true
			break
		}
	}
	if !hasControl {
		return s
	}
	// Strip complete ANSI CSI sequences first (ESC[...m, ESC[2J, etc.)
	s = ansiRE.ReplaceAllString(s, "")
	// Strip any remaining control characters (lone ESC, \n, \r, \t, NUL, DEL…)
	b := make([]rune, 0, len([]rune(s)))
	for _, r := range s {
		if r >= 32 && r != 127 {
			b = append(b, r)
		}
	}
	return string(b)
}

// sanitizeArgs sanitizes all string values in args in-place (returning a new slice).
// Non-string values (int, float, bool, etc.) are passed through unchanged.
func sanitizeArgs(args []any) []any {
	result := make([]any, len(args))
	for i, a := range args {
		if s, ok := a.(string); ok {
			result[i] = sanitize(s)
		} else {
			result[i] = a
		}
	}
	return result
}

// Printf sanitizes all string args then writes to stdout.
// Safe drop-in for fmt.Printf when args may include user or external data.
func Printf(format string, args ...any) {
	fmt.Printf(format, sanitizeArgs(args)...)
}

// Println sanitizes all string args then writes to stdout with a trailing newline.
// Safe drop-in for fmt.Println.
func Println(args ...any) {
	fmt.Println(sanitizeArgs(args)...)
}

// Print sanitizes all string args then writes to stdout without a newline.
func Print(args ...any) {
	fmt.Print(sanitizeArgs(args)...)
}

// Fprintf sanitizes all string args then writes to w.
// Use for stderr output that includes user or external data.
func Fprintf(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, sanitizeArgs(args)...)
}

// Errorf formats a string with sanitized string args.
// Returns a string (not an error) — intended for building user-facing messages
// before wrapping in fmt.Errorf or errors.New.
func Errorf(format string, args ...any) string {
	return fmt.Sprintf(format, sanitizeArgs(args)...)
}

// Warnf writes a sanitized warning line to stderr.
func Warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", sanitizeArgs(args)...)
}
