package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/zengyuxiu/agentguardian/internal/rules"
)

func TestHandlerApplyRuntime(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	service := NewService(configDir, filepath.Join(configDir, "agentguardd.sock"), 10*time.Millisecond, &fakeApplier{})
	if err := service.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}
	defer service.Close()

	reqBody, err := json.Marshal(ApplyRuntimeRequest{
		Ruleset: rules.Ruleset{
			Version: 1,
			Rules: []rules.Rule{
				{
					ID: "runtime-hide",
					Match: rules.MatchSpec{
						Path: "/tmp/runtime",
						Comm: "cat",
					},
					Action: rules.ActionSpec{
						Type: rules.ActionHide,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/runtime/apply", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()

	NewHandler(service).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp ApplyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if resp.Scope != ScopeRuntime {
		t.Fatalf("scope = %q, want %q", resp.Scope, ScopeRuntime)
	}
	if !resp.Runtime.Loaded || !resp.Runtime.Valid {
		t.Fatalf("runtime state = %+v, want loaded+valid", resp.Runtime)
	}
}

func TestHandlerSaveRuntime(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	service := NewService(configDir, filepath.Join(configDir, "agentguardd.sock"), 10*time.Millisecond, &fakeApplier{})
	if err := service.EnsureLayout(); err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}
	defer service.Close()

	if _, err := service.ApplyRuntime(rules.Ruleset{
		Version: 1,
		Rules: []rules.Rule{
			{
				ID: "runtime-hide",
				Match: rules.MatchSpec{
					Path: "/tmp/runtime",
					Comm: "cat",
				},
				Action: rules.ActionSpec{
					Type: rules.ActionHide,
				},
			},
		},
	}); err != nil {
		t.Fatalf("ApplyRuntime() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/runtime/save", nil)
	rec := httptest.NewRecorder()

	NewHandler(service).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp SaveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if resp.Permanent.RuleCount != 1 {
		t.Fatalf("permanent rule count = %d, want 1", resp.Permanent.RuleCount)
	}
}
