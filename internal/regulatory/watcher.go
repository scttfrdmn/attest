// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package regulatory

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxDocumentBytes = 1 << 20  // 1 MB — prevents OOM on large Federal Register PDFs
	maxFullTextRunes = 12_000   // truncate before AI analysis
	fetchTimeout     = 30 * time.Second
)

// Notice is a regulatory notice fetched from a source.
type Notice struct {
	// ID is a stable source-specific identifier (e.g. "NOT-OD-25-081", "FR-2026-04567").
	ID string
	// Title is the notice title.
	Title string
	// Source is the Source.ID this notice came from.
	Source string
	// PublishedAt is when the notice was published.
	PublishedAt time.Time
	// URL is the canonical URL for the notice.
	URL string
	// Abstract is the short description from the feed.
	Abstract string
	// FullText is the fetched full document content, truncated to maxFullTextRunes.
	// Empty until FetchDocument is called.
	FullText string
}

// Watcher fetches regulatory notices from configured sources.
type Watcher struct {
	client          *http.Client
	skipURLValidate bool // true only in tests
}

// NewWatcherWithClient creates a Watcher using a custom HTTP client.
// URL validation is skipped so tests can use httptest servers.
func NewWatcherWithClient(client *http.Client) *Watcher {
	return &Watcher{client: client, skipURLValidate: true}
}

// NewWatcher creates a Watcher with SSRF-protected HTTP client.
func NewWatcher() *Watcher {
	return &Watcher{
		client: &http.Client{
			Timeout: fetchTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Validate redirect targets against SSRF rules.
				if err := validateURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect blocked: %w", err)
				}
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// FetchNew returns notices from src published after since.
// Only notices containing at least one keyword from src.Keywords are returned
// (unless Keywords is empty, in which case all notices are returned).
func (w *Watcher) FetchNew(ctx context.Context, src Source, since time.Time) ([]Notice, error) {
	if !w.skipURLValidate {
		if err := validateURL(src.FeedURL); err != nil {
			return nil, fmt.Errorf("source %s: %w", src.ID, err)
		}
	}

	switch src.FeedType {
	case FeedTypeRSS, FeedTypeAtom:
		return w.fetchRSS(ctx, src, since)
	case FeedTypeFederalRegisterAPI:
		return w.fetchFederalRegister(ctx, src, since)
	case FeedTypeGitHubReleases:
		return w.fetchGitHubReleases(ctx, src, since)
	default:
		return nil, fmt.Errorf("unsupported feed type: %s", src.FeedType)
	}
}

// FetchDocument retrieves the full text of a notice URL.
// The result is truncated to maxFullTextRunes for AI analysis.
func (w *Watcher) FetchDocument(ctx context.Context, rawURL string) (string, error) {
	if err := validateURL(rawURL); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "attest-regulatory-watcher/1.0")
	req.Header.Set("Accept", "text/html,text/plain,application/pdf")

	resp, err := w.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", rawURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", rawURL, err)
	}

	text := extractText(string(body), resp.Header.Get("Content-Type"))
	runes := []rune(text)
	if len(runes) > maxFullTextRunes {
		text = string(runes[:maxFullTextRunes]) + "\n[truncated]"
	}
	return text, nil
}

// --- RSS/Atom parsing --------------------------------------------------------

type rssFeed struct {
	XMLName xml.Name  `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}

func (w *Watcher) fetchRSS(ctx context.Context, src Source, since time.Time) ([]Notice, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.FeedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "attest-regulatory-watcher/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch rss %s: %w", src.FeedURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, err
	}

	var feed rssFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("parse rss: %w", err)
	}

	var notices []Notice
	for _, item := range feed.Channel.Items {
		pub, _ := time.Parse(time.RFC1123, item.PubDate)
		if pub.Before(since) {
			continue
		}
		if !matchesKeywords(item.Title+" "+item.Description, src.Keywords) {
			continue
		}
		id := extractNoticeID(item.GUID, item.Link, item.Title)
		notices = append(notices, Notice{
			ID:          id,
			Title:       item.Title,
			Source:      src.ID,
			PublishedAt: pub,
			URL:         item.Link,
			Abstract:    stripHTML(item.Description),
		})
	}
	return notices, nil
}

// --- Federal Register API ----------------------------------------------------

type frAPIResponse struct {
	Results []frDocument `json:"results"`
}

type frDocument struct {
	DocumentNumber string `json:"document_number"`
	Title          string `json:"title"`
	Abstract       string `json:"abstract"`
	PublicationDate string `json:"publication_date"`
	HTMLUrl        string `json:"html_url"`
}

func (w *Watcher) fetchFederalRegister(ctx context.Context, src Source, since time.Time) ([]Notice, error) {
	apiURL := src.FeedURL + "&conditions[publication_date][gte]=" + since.Format("2006-01-02")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "attest-regulatory-watcher/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch federal register: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, err
	}

	var apiResp frAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parse federal register response: %w", err)
	}

	var notices []Notice
	for _, doc := range apiResp.Results {
		pub, _ := time.Parse("2006-01-02", doc.PublicationDate)
		if !matchesKeywords(doc.Title+" "+doc.Abstract, src.Keywords) {
			continue
		}
		notices = append(notices, Notice{
			ID:          "FR-" + doc.DocumentNumber,
			Title:       doc.Title,
			Source:      src.ID,
			PublishedAt: pub,
			URL:         doc.HTMLUrl,
			Abstract:    doc.Abstract,
		})
	}
	return notices, nil
}

// --- GitHub Releases ---------------------------------------------------------

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
}

func (w *Watcher) fetchGitHubReleases(ctx context.Context, src Source, since time.Time) ([]Notice, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.FeedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "attest-regulatory-watcher/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch github releases: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, err
	}

	var releases []ghRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("parse github releases: %w", err)
	}

	var notices []Notice
	for _, rel := range releases {
		if rel.PublishedAt.Before(since) {
			continue
		}
		notices = append(notices, Notice{
			ID:          src.ID + "-" + rel.TagName,
			Title:       rel.Name,
			Source:      src.ID,
			PublishedAt: rel.PublishedAt,
			URL:         rel.HTMLURL,
			Abstract:    truncateString(rel.Body, 500),
		})
	}
	return notices, nil
}

// --- SSRF protection ---------------------------------------------------------

// validateURL rejects URLs that could be used for SSRF attacks.
// Allows only https scheme, public IPs, and non-localhost hostnames.
func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only https URLs allowed (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	// Reject localhost variants.
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return fmt.Errorf("localhost URLs not allowed")
	}
	// Reject private IP ranges.
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("private IP address not allowed: %s", host)
		}
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

var privateRanges = func() []*net.IPNet {
	blocks := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "fc00::/7", "fe80::/10",
	}
	var ranges []*net.IPNet
	for _, b := range blocks {
		_, block, _ := net.ParseCIDR(b)
		ranges = append(ranges, block)
	}
	return ranges
}()

// --- Helpers -----------------------------------------------------------------

func matchesKeywords(text string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	lower := strings.ToLower(text)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func extractNoticeID(guid, link, title string) string {
	// Try to extract NOT-OD-25-081 style ID from URL or title.
	for _, candidate := range []string{guid, link, title} {
		for _, prefix := range []string{"NOT-OD-", "NOT-MH-", "NOT-CA-", "PA-", "RFA-"} {
			if idx := strings.Index(strings.ToUpper(candidate), prefix); idx >= 0 {
				end := idx + len(prefix) + 8
				if end > len(candidate) {
					end = len(candidate)
				}
				id := strings.ToUpper(candidate[idx:end])
				id = strings.TrimRight(id, "/ ")
				if len(id) >= len(prefix)+2 {
					return id
				}
			}
		}
	}
	// Fall back to URL hash or GUID.
	if guid != "" {
		return guid
	}
	return link
}

func stripHTML(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func extractText(body, contentType string) string {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "html") {
		return stripHTML(body)
	}
	// PDF, plain text, etc. — return as-is (PDF parsing would require external library).
	return body
}

func truncateString(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}
