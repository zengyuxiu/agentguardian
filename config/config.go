package config

import "flag"

type Config struct {
	TargetPath         string
	RewritePID         uint
	HidePID            uint
	RewriteComms       string
	HideComms          string
	RewriteExes        string
	HideExes           string
	FindText           string
	ReplaceText        string
	RewritePIDExplicit bool
}

func ParseFlags(args []string, selfPID uint) (Config, error) {
	cfg := Config{}
	fs := flag.NewFlagSet("agentguardian", flag.ContinueOnError)

	fs.StringVar(&cfg.TargetPath, "path", "/etc/passwd", "sensitive path to watch")
	fs.UintVar(&cfg.RewritePID, "rewrite-pid", selfPID, "pid to receive rewritten content")
	fs.UintVar(&cfg.HidePID, "hide-pid", 0, "pid to deny access with ENOENT")
	fs.StringVar(&cfg.RewriteComms, "rewrite-comm", "", "comma-separated process names to receive rewritten content, for example cat,less")
	fs.StringVar(&cfg.HideComms, "hide-comm", "", "comma-separated process names to deny with ENOENT, for example cat,ls")
	fs.StringVar(&cfg.RewriteExes, "rewrite-exe", "", "comma-separated executable paths to receive rewritten content, for example /usr/bin/cat")
	fs.StringVar(&cfg.HideExes, "hide-exe", "", "comma-separated executable paths to deny with ENOENT, for example /usr/bin/cat")
	fs.StringVar(&cfg.FindText, "find", "", "text to find inside the intercepted read buffer")
	fs.StringVar(&cfg.ReplaceText, "replace", "", "replacement text written over each matched occurrence; must have the same length as -find")
	fs.StringVar(&cfg.ReplaceText, "rewrite", "", "deprecated alias of -replace")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	fs.Visit(func(f *flag.Flag) {
		if f.Name == "rewrite-pid" {
			cfg.RewritePIDExplicit = true
		}
	})

	return cfg, nil
}

func (cfg Config) RewriteRequested() bool {
	if cfg.RewritePIDExplicit || cfg.RewriteComms != "" || cfg.RewriteExes != "" {
		return true
	}

	return cfg.FindText != "" || cfg.ReplaceText != ""
}

func (cfg Config) ShouldApplyRewritePID() bool {
	if !cfg.RewriteRequested() {
		return false
	}

	if cfg.RewritePID == 0 {
		return false
	}

	if cfg.RewritePIDExplicit {
		return true
	}

	return cfg.RewriteComms == "" && cfg.RewriteExes == ""
}

func (cfg Config) EffectiveRewritePID() uint {
	if !cfg.ShouldApplyRewritePID() {
		return 0
	}

	return cfg.RewritePID
}
