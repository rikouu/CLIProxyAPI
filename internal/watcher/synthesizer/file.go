package synthesizer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/geminicli"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// FileSynthesizer generates Auth entries from OAuth JSON files.
// It handles file-based authentication and Gemini virtual auth generation.
type FileSynthesizer struct{}

// NewFileSynthesizer creates a new FileSynthesizer instance.
func NewFileSynthesizer() *FileSynthesizer {
	return &FileSynthesizer{}
}

// Synthesize generates Auth entries from auth files in the auth directory.
func (s *FileSynthesizer) Synthesize(ctx *SynthesisContext) ([]*coreauth.Auth, error) {
	out := make([]*coreauth.Auth, 0, 16)
	if ctx == nil || ctx.AuthDir == "" {
		return out, nil
	}

	entries, err := os.ReadDir(ctx.AuthDir)
	if err != nil {
		// Not an error if directory doesn't exist
		return out, nil
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		full := filepath.Join(ctx.AuthDir, name)
		data, errRead := os.ReadFile(full)
		if errRead != nil || len(data) == 0 {
			continue
		}
		auths := synthesizeFileAuths(ctx, full, data)
		if len(auths) == 0 {
			continue
		}
		out = append(out, auths...)
	}
	return out, nil
}

// SynthesizeAuthFile generates Auth entries for one auth JSON file payload.
// It shares exactly the same mapping behavior as FileSynthesizer.Synthesize.
func SynthesizeAuthFile(ctx *SynthesisContext, fullPath string, data []byte) []*coreauth.Auth {
	return synthesizeFileAuths(ctx, fullPath, data)
}

func synthesizeFileAuths(ctx *SynthesisContext, fullPath string, data []byte) []*coreauth.Auth {
	if ctx == nil || len(data) == 0 {
		return nil
	}
	now := ctx.Now
	cfg := ctx.Config
	var metadata map[string]any
	if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
		return nil
	}
	t, _ := metadata["type"].(string)
	if t == "" {
		return nil
	}
	provider := strings.ToLower(t)
	if provider == "gemini" {
		provider = "gemini-cli"
	}
	label := provider
	if email, _ := metadata["email"].(string); email != "" {
		label = email
	}
	// Use relative path under authDir as ID to stay consistent with the file-based token store.
	id := fullPath
	if strings.TrimSpace(ctx.AuthDir) != "" {
		if rel, errRel := filepath.Rel(ctx.AuthDir, fullPath); errRel == nil && rel != "" {
			id = rel
		}
	}
	if runtime.GOOS == "windows" {
		id = strings.ToLower(id)
	}

	proxyURL := ""
	if p, ok := metadata["proxy_url"].(string); ok {
		proxyURL = p
	}

	prefix := ""
	if rawPrefix, ok := metadata["prefix"].(string); ok {
		trimmed := strings.TrimSpace(rawPrefix)
		trimmed = strings.Trim(trimmed, "/")
		if trimmed != "" && !strings.Contains(trimmed, "/") {
			prefix = trimmed
		}
	}

	disabled, _ := metadata["disabled"].(bool)
	status := coreauth.StatusActive
	if disabled {
		status = coreauth.StatusDisabled
	}

	// Read per-account excluded models from the OAuth JSON file.
	perAccountExcluded := extractExcludedModelsFromMetadata(metadata)

	a := &coreauth.Auth{
		ID:       id,
		Provider: provider,
		Label:    label,
		Prefix:   prefix,
		Status:   status,
		Disabled: disabled,
		Attributes: map[string]string{
			"source": fullPath,
			"path":   fullPath,
		},
		ProxyURL:  proxyURL,
		Metadata:  metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
	// Read priority from auth file.
	if rawPriority, ok := metadata["priority"]; ok {
		switch v := rawPriority.(type) {
		case float64:
			a.Attributes["priority"] = strconv.Itoa(int(v))
		case string:
			priority := strings.TrimSpace(v)
			if _, errAtoi := strconv.Atoi(priority); errAtoi == nil {
				a.Attributes["priority"] = priority
			}
		}
	}
	// Read note from auth file.
	if rawNote, ok := metadata["note"]; ok {
		if note, isStr := rawNote.(string); isStr {
			if trimmed := strings.TrimSpace(note); trimmed != "" {
				a.Attributes["note"] = trimmed
			}
		}
	}
	ApplyAuthExcludedModelsMeta(a, cfg, perAccountExcluded, "oauth")
	// Assign a deterministic per-account device fingerprint for Claude OAuth accounts.
	// This makes each account look like a different real device (macOS/Windows, different Node versions).
	if provider == "claude" {
		applyClaudeDeviceFingerprint(a)
		// Propagate rate-limit config from JSON fields to Attributes for the executor.
		applyClaudeRateLimitAttrs(a, metadata)
	}
	// For codex auth files, extract plan_type from the JWT id_token.
	if provider == "codex" {
		if idTokenRaw, ok := metadata["id_token"].(string); ok && strings.TrimSpace(idTokenRaw) != "" {
			if claims, errParse := codex.ParseJWTToken(idTokenRaw); errParse == nil && claims != nil {
				if pt := strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType); pt != "" {
					a.Attributes["plan_type"] = pt
				}
			}
		}
	}
	if provider == "gemini-cli" {
		if virtuals := SynthesizeGeminiVirtualAuths(a, metadata, now); len(virtuals) > 0 {
			for _, v := range virtuals {
				ApplyAuthExcludedModelsMeta(v, cfg, perAccountExcluded, "oauth")
			}
			out := make([]*coreauth.Auth, 0, 1+len(virtuals))
			out = append(out, a)
			out = append(out, virtuals...)
			return out
		}
	}
	return []*coreauth.Auth{a}
}

// SynthesizeGeminiVirtualAuths creates virtual Auth entries for multi-project Gemini credentials.
// It disables the primary auth and creates one virtual auth per project.
func SynthesizeGeminiVirtualAuths(primary *coreauth.Auth, metadata map[string]any, now time.Time) []*coreauth.Auth {
	if primary == nil || metadata == nil {
		return nil
	}
	projects := splitGeminiProjectIDs(metadata)
	if len(projects) <= 1 {
		return nil
	}
	email, _ := metadata["email"].(string)
	shared := geminicli.NewSharedCredential(primary.ID, email, metadata, projects)
	primary.Disabled = true
	primary.Status = coreauth.StatusDisabled
	primary.Runtime = shared
	if primary.Attributes == nil {
		primary.Attributes = make(map[string]string)
	}
	primary.Attributes["gemini_virtual_primary"] = "true"
	primary.Attributes["virtual_children"] = strings.Join(projects, ",")
	source := primary.Attributes["source"]
	authPath := primary.Attributes["path"]
	originalProvider := primary.Provider
	if originalProvider == "" {
		originalProvider = "gemini-cli"
	}
	label := primary.Label
	if label == "" {
		label = originalProvider
	}
	virtuals := make([]*coreauth.Auth, 0, len(projects))
	for _, projectID := range projects {
		attrs := map[string]string{
			"runtime_only":           "true",
			"gemini_virtual_parent":  primary.ID,
			"gemini_virtual_project": projectID,
		}
		if source != "" {
			attrs["source"] = source
		}
		if authPath != "" {
			attrs["path"] = authPath
		}
		// Propagate priority from primary auth to virtual auths
		if priorityVal, hasPriority := primary.Attributes["priority"]; hasPriority && priorityVal != "" {
			attrs["priority"] = priorityVal
		}
		// Propagate note from primary auth to virtual auths
		if noteVal, hasNote := primary.Attributes["note"]; hasNote && noteVal != "" {
			attrs["note"] = noteVal
		}
		metadataCopy := map[string]any{
			"email":             email,
			"project_id":        projectID,
			"virtual":           true,
			"virtual_parent_id": primary.ID,
			"type":              metadata["type"],
		}
		if v, ok := metadata["disable_cooling"]; ok {
			metadataCopy["disable_cooling"] = v
		} else if v, ok := metadata["disable-cooling"]; ok {
			metadataCopy["disable_cooling"] = v
		}
		if v, ok := metadata["request_retry"]; ok {
			metadataCopy["request_retry"] = v
		} else if v, ok := metadata["request-retry"]; ok {
			metadataCopy["request_retry"] = v
		}
		proxy := strings.TrimSpace(primary.ProxyURL)
		if proxy != "" {
			metadataCopy["proxy_url"] = proxy
		}
		virtual := &coreauth.Auth{
			ID:         buildGeminiVirtualID(primary.ID, projectID),
			Provider:   originalProvider,
			Label:      fmt.Sprintf("%s [%s]", label, projectID),
			Status:     coreauth.StatusActive,
			Attributes: attrs,
			Metadata:   metadataCopy,
			ProxyURL:   primary.ProxyURL,
			Prefix:     primary.Prefix,
			CreatedAt:  primary.CreatedAt,
			UpdatedAt:  primary.UpdatedAt,
			Runtime:    geminicli.NewVirtualCredential(projectID, shared),
		}
		virtuals = append(virtuals, virtual)
	}
	return virtuals
}

// splitGeminiProjectIDs extracts and deduplicates project IDs from metadata.
func splitGeminiProjectIDs(metadata map[string]any) []string {
	raw, _ := metadata["project_id"].(string)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

// buildGeminiVirtualID constructs a virtual auth ID from base ID and project ID.
func buildGeminiVirtualID(baseID, projectID string) string {
	project := strings.TrimSpace(projectID)
	if project == "" {
		project = "project"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_")
	return fmt.Sprintf("%s::%s", baseID, replacer.Replace(project))
}

// extractExcludedModelsFromMetadata reads per-account excluded models from the OAuth JSON metadata.
// Supports both "excluded_models" and "excluded-models" keys, and accepts both []string and []interface{}.
func extractExcludedModelsFromMetadata(metadata map[string]any) []string {
	if metadata == nil {
		return nil
	}
	// Try both key formats
	raw, ok := metadata["excluded_models"]
	if !ok {
		raw, ok = metadata["excluded-models"]
	}
	if !ok || raw == nil {
		return nil
	}
	var stringSlice []string
	switch v := raw.(type) {
	case []string:
		stringSlice = v
	case []interface{}:
		stringSlice = make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				stringSlice = append(stringSlice, s)
			}
		}
	default:
		return nil
	}
	result := make([]string, 0, len(stringSlice))
	for _, s := range stringSlice {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// claudeDeviceFingerprint holds a simulated device profile for Claude OAuth requests.
type claudeDeviceFingerprint struct {
	userAgent      string
	stainlessOS    string
	stainlessArch  string
	nodeVersion    string
	pkgVersion     string
}

// claudeDevicePool is the pool of realistic device profiles to randomize from.
// Profiles are based on real Claude Code CLI installations on macOS and Windows.
var claudeDevicePool = []claudeDeviceFingerprint{
	{"claude-cli/2.1.81 (external, cli)", "macOS", "arm64", "v22.14.0", "0.74.0"},
	{"claude-cli/2.1.81 (external, cli)", "macOS", "x64", "v22.14.0", "0.74.0"},
	{"claude-cli/2.1.81 (external, cli)", "macOS", "arm64", "v22.13.0", "0.74.0"},
	{"claude-cli/2.1.78 (external, cli)", "macOS", "arm64", "v22.12.0", "0.74.0"},
	{"claude-cli/2.1.78 (external, cli)", "macOS", "x64", "v22.12.0", "0.74.0"},
	{"claude-cli/2.1.75 (external, cli)", "macOS", "arm64", "v22.11.0", "0.73.0"},
	{"claude-cli/2.1.81 (external, cli)", "Windows_NT", "x64", "v22.14.0", "0.74.0"},
	{"claude-cli/2.1.78 (external, cli)", "Windows_NT", "x64", "v22.12.0", "0.74.0"},
	{"claude-cli/2.1.75 (external, cli)", "Windows_NT", "x64", "v22.11.0", "0.73.0"},
	{"claude-cli/2.1.81 (external, cli)", "macOS", "arm64", "v20.18.3", "0.74.0"},
	{"claude-cli/2.1.78 (external, cli)", "macOS", "arm64", "v20.18.2", "0.74.0"},
	{"claude-cli/2.1.75 (external, cli)", "Windows_NT", "x64", "v20.18.1", "0.73.0"},
}

// pickClaudeDeviceFingerprint deterministically picks a fingerprint for a given account ID.
// Using a hash of the account ID ensures the same account always gets the same fingerprint
// across restarts, while different accounts get different fingerprints.
func pickClaudeDeviceFingerprint(accountID string) claudeDeviceFingerprint {
	h := sha256.Sum256([]byte(accountID))
	idx := binary.BigEndian.Uint64(h[:8]) % uint64(len(claudeDevicePool))
	return claudeDevicePool[idx]
}

// applyClaudeDeviceFingerprint sets per-account device fingerprint headers on the auth,
// unless the account has already configured custom User-Agent/stainless headers.
func applyClaudeDeviceFingerprint(a *coreauth.Auth) {
	if a == nil || a.Attributes == nil {
		return
	}
	// Don't override if user explicitly set custom headers
	if _, hasUA := a.Attributes["header:User-Agent"]; hasUA {
		return
	}
	if _, hasOS := a.Attributes["header:X-Stainless-Os"]; hasOS {
		return
	}
	fp := pickClaudeDeviceFingerprint(a.ID)
	a.Attributes["header:User-Agent"] = fp.userAgent
	a.Attributes["header:X-Stainless-Os"] = fp.stainlessOS
	a.Attributes["header:X-Stainless-Arch"] = fp.stainlessArch
	a.Attributes["header:X-Stainless-Runtime-Version"] = fp.nodeVersion
	a.Attributes["header:X-Stainless-Package-Version"] = fp.pkgVersion
}

// applyClaudeRateLimitAttrs copies rate-limit fields from auth JSON metadata
// to auth Attributes so the executor can read them without importing synthesizer.
// Supported JSON fields: "rpm", "max_concurrency", "min_interval_ms"
func applyClaudeRateLimitAttrs(a *coreauth.Auth, metadata map[string]any) {
	if a == nil || metadata == nil {
		return
	}
	if a.Attributes == nil {
		a.Attributes = make(map[string]string)
	}
	for _, key := range []string{"rpm", "max_concurrency", "min_interval_ms"} {
		val, ok := metadata[key]
		if !ok {
			continue
		}
		var s string
		switch v := val.(type) {
		case float64:
			if v > 0 {
				s = strconv.Itoa(int(v))
			}
		case int:
			if v > 0 {
				s = strconv.Itoa(v)
			}
		case string:
			s = strings.TrimSpace(v)
		}
		if s != "" {
			a.Attributes[key] = s
		}
	}
}
