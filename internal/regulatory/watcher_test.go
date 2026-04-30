// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package regulatory_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/provabl/attest/internal/regulatory"
)

// --- validateURL (SSRF protection) -------------------------------------------

func TestValidateURLRejectsHTTP(t *testing.T) {
	w := regulatory.NewWatcher()
	_, err := w.FetchDocument(context.Background(), "http://example.com/notice.html")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Error("FetchDocument must reject non-https URLs")
	}
}

func TestValidateURLRejectsLocalhost(t *testing.T) {
	w := regulatory.NewWatcher()
	_, err := w.FetchDocument(context.Background(), "https://localhost/internal")
	if err == nil {
		t.Error("FetchDocument must reject localhost URLs")
	}
}

func TestValidateURLRejectsPrivateIP(t *testing.T) {
	w := regulatory.NewWatcher()
	_, err := w.FetchDocument(context.Background(), "https://192.168.1.1/data")
	if err == nil {
		t.Error("FetchDocument must reject private IP addresses")
	}
}

func TestValidateURLRejects10Block(t *testing.T) {
	w := regulatory.NewWatcher()
	_, err := w.FetchDocument(context.Background(), "https://10.0.0.1/secret")
	if err == nil {
		t.Error("FetchDocument must reject 10.x.x.x private addresses")
	}
}

// --- RSS parsing -------------------------------------------------------------

func TestFetchRSSParsesNIHGuideFormat(t *testing.T) {
	feed := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <item>
      <title>NOT-OD-25-081: Policy on AI/ML Models Trained on Controlled-Access Data</title>
      <link>https://grants.nih.gov/grants/guide/notice-files/NOT-OD-25-081.html</link>
      <description>NIH policy requiring that model parameters constitute data derivatives.</description>
      <pubDate>Tue, 15 Apr 2025 00:00:00 +0000</pubDate>
      <guid>https://grants.nih.gov/grants/guide/notice-files/NOT-OD-25-081.html</guid>
    </item>
    <item>
      <title>NOT-OD-25-999: Administrative update to forms</title>
      <link>https://grants.nih.gov/grants/guide/notice-files/NOT-OD-25-999.html</link>
      <description>Minor administrative update to application forms.</description>
      <pubDate>Mon, 14 Apr 2025 00:00:00 +0000</pubDate>
      <guid>NOT-OD-25-999</guid>
    </item>
  </channel>
</rss>`

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, feed)
	}))
	defer srv.Close()

	src := regulatory.Source{
		ID:       "test-nih",
		Name:     "Test NIH",
		FeedURL:  srv.URL,
		FeedType: regulatory.FeedTypeRSS,
		// "AI/ML" only matches the first item, not the administrative update
		Keywords: []string{"AI/ML", "data derivatives", "controlled-access"},
	}

	// Use a watcher that trusts the test TLS cert.
	w := regulatory.NewWatcherWithClient(srv.Client())
	since := time.Date(2025, 4, 10, 0, 0, 0, 0, time.UTC)
	notices, err := w.FetchNew(context.Background(), src, since)
	if err != nil {
		t.Fatalf("FetchNew failed: %v", err)
	}

	// Only the NOT-OD-25-081 notice should match (keyword "NOT-OD-" matches)
	if len(notices) != 1 {
		t.Fatalf("expected 1 notice (keyword-filtered), got %d", len(notices))
	}
	if !strings.Contains(notices[0].ID, "NOT-OD-25-081") {
		t.Errorf("expected notice ID to contain NOT-OD-25-081, got %q", notices[0].ID)
	}
	if notices[0].Source != "test-nih" {
		t.Errorf("expected source test-nih, got %q", notices[0].Source)
	}
}

// --- DefaultSources ----------------------------------------------------------

func TestDefaultSourcesReturnsAtLeastFour(t *testing.T) {
	sources := regulatory.DefaultSources()
	if len(sources) < 4 {
		t.Errorf("expected at least 4 default sources, got %d", len(sources))
	}
	ids := make(map[string]bool)
	for _, s := range sources {
		if s.ID == "" {
			t.Error("source has empty ID")
		}
		if s.FeedURL == "" {
			t.Error("source has empty FeedURL")
		}
		if s.Label == "" {
			t.Errorf("source %q has empty Label", s.ID)
		}
		if ids[s.ID] {
			t.Errorf("duplicate source ID: %q", s.ID)
		}
		ids[s.ID] = true
	}
	// Check required sources exist.
	for _, required := range []string{"nih-guide", "nist-csrc", "federal-register-hhs", "federal-register-dod"} {
		if !ids[required] {
			t.Errorf("required source %q not in DefaultSources()", required)
		}
	}
}

// --- Store deduplication -----------------------------------------------------

func TestStoreDeduplicates(t *testing.T) {
	dir := t.TempDir()
	store := regulatory.NewStore(dir)

	if store.IsProcessed("NOT-OD-25-081") {
		t.Error("notice should not be processed before MarkProcessed")
	}
	if err := store.MarkProcessed("NOT-OD-25-081", true); err != nil {
		t.Fatalf("MarkProcessed failed: %v", err)
	}
	if !store.IsProcessed("NOT-OD-25-081") {
		t.Error("notice should be processed after MarkProcessed")
	}
	// Different ID is not affected.
	if store.IsProcessed("NOT-OD-25-082") {
		t.Error("different notice ID should not be marked processed")
	}
}
