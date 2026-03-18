package config

import "testing"

func TestRewriteRequested(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "hide only",
			cfg: Config{
				HideExes:   "/opt/claude-code/bin/claude",
				TargetPath: "/tmp/replacetest",
			},
			want: false,
		},
		{
			name: "rewrite pid",
			cfg: Config{
				RewritePID:         1234,
				RewritePIDExplicit: true,
			},
			want: true,
		},
		{
			name: "rewrite comm",
			cfg: Config{
				RewriteComms: "cat",
			},
			want: true,
		},
		{
			name: "rewrite exe",
			cfg: Config{
				RewriteExes: "/usr/bin/node",
			},
			want: true,
		},
		{
			name: "find replace only",
			cfg: Config{
				RewritePID:  1234,
				FindText:    "secret",
				ReplaceText: "public",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.RewriteRequested(); got != tt.want {
				t.Fatalf("RewriteRequested() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFlagsRulesPath(t *testing.T) {
	cfg, err := ParseFlags([]string{"-rules", "/etc/agentguardian/rules.d"}, 1234)
	if err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}

	if cfg.RulesPath != "/etc/agentguardian/rules.d" {
		t.Fatalf("ParseFlags() rules path = %q, want %q", cfg.RulesPath, "/etc/agentguardian/rules.d")
	}
}

func TestShouldApplyRewritePID(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "default self rewrite when only find replace provided",
			cfg: Config{
				RewritePID:  1234,
				FindText:    "secret",
				ReplaceText: "public",
			},
			want: true,
		},
		{
			name: "hide only does not apply implicit rewrite pid",
			cfg: Config{
				RewritePID: 1234,
				HideExes:   "/opt/claude-code/bin/claude",
			},
			want: false,
		},
		{
			name: "rewrite exe without explicit pid does not also rewrite self",
			cfg: Config{
				RewritePID:  1234,
				RewriteExes: "/usr/bin/node",
				FindText:    "secret",
				ReplaceText: "public",
			},
			want: false,
		},
		{
			name: "explicit rewrite pid still applies",
			cfg: Config{
				RewritePID:         1234,
				RewritePIDExplicit: true,
				FindText:           "secret",
				ReplaceText:        "public",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.ShouldApplyRewritePID(); got != tt.want {
				t.Fatalf("ShouldApplyRewritePID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEffectiveRewritePID(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want uint
	}{
		{
			name: "hide only reports zero",
			cfg: Config{
				RewritePID: 1234,
				HideExes:   "/opt/claude-code/bin/claude",
			},
			want: 0,
		},
		{
			name: "implicit self rewrite reports pid",
			cfg: Config{
				RewritePID:  1234,
				FindText:    "secret",
				ReplaceText: "public",
			},
			want: 1234,
		},
		{
			name: "explicit rewrite pid reports pid",
			cfg: Config{
				RewritePID:         1234,
				RewritePIDExplicit: true,
				FindText:           "secret",
				ReplaceText:        "public",
			},
			want: 1234,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.EffectiveRewritePID(); got != tt.want {
				t.Fatalf("EffectiveRewritePID() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBuildExecutablePoliciesHideOnlyDoesNotRequireRewriteConfig(t *testing.T) {
	cfg := Config{
		TargetPath: "/tmp/replacetest",
		HideExes:   "/opt/claude-code/bin/claude",
	}

	if _, err := buildExecutablePolicies(cfg); err != nil {
		t.Fatalf("buildExecutablePolicies() returned error for hide-only config: %v", err)
	}
}

func TestBuildExecutablePoliciesRewriteStillRequiresFindAndReplace(t *testing.T) {
	cfg := Config{
		TargetPath:  "/tmp/replacetest",
		RewriteExes: "/usr/bin/node",
	}

	if _, err := buildExecutablePolicies(cfg); err == nil {
		t.Fatal("buildExecutablePolicies() should require -find/-replace for rewrite configs")
	}
}
