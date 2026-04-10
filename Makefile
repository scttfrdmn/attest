.PHONY: build test vet vuln scan-fs scan-iac sast security

# ── Build & Test ─────────────────────────────────────────────────────

build:
	go build ./cmd/attest

test:
	go test ./...

vet:
	go vet ./...

# ── Security Scanning ───────────────────────────────────────────────

vuln: ## Go dependency vulnerability check (call-graph aware)
	govulncheck ./...

scan-fs: ## Trivy filesystem scan for known vulnerabilities
	trivy fs --severity HIGH,CRITICAL .

scan-iac: ## Trivy IaC misconfiguration scan
	trivy config .

sast: ## Semgrep static analysis
	semgrep scan --config=auto --error .

security: vuln scan-fs scan-iac sast ## Run all security checks
