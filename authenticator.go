// Package auth provides OIDC login, signed session cookies and permission
// middleware for Datasektionen systems.
package auth

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// MinSecretKeyLength is the minimum accepted length of Config.SessionSecretKey in bytes.
const MinSecretKeyLength = 32

// Config configures an Authenticator.
type Config struct {
	ProviderURL       string        // OIDC provider URL, e.g. "https://sso.datasektionen.se/op"
	ClientID          string        // OAuth2 client ID
	ClientSecret      string        // OAuth2 client secret
	RedirectURL       string        // Absolute URL that routes to CallbackPath
	SessionSecretKey  string        // Signs session and state tokens, at least MinSecretKeyLength bytes
	SessionCookieName string        // Default "session"
	StateCookieName   string        // Default "oauth_state"
	SessionDuration   time.Duration // Default 7 days
}

// ConfigFromEnv reads OIDC_PROVIDER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
// OIDC_REDIRECT_URL and APP_SECRET_KEY. Validation happens in New.
func ConfigFromEnv() Config {
	return Config{
		ProviderURL:      os.Getenv("OIDC_PROVIDER"),
		ClientID:         os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:     os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:      os.Getenv("OIDC_REDIRECT_URL"),
		SessionSecretKey: os.Getenv("APP_SECRET_KEY"),
	}
}

func (c Config) validate() error {
	var missing []string
	if c.ProviderURL == "" {
		missing = append(missing, "ProviderURL (OIDC_PROVIDER)")
	}
	if c.ClientID == "" {
		missing = append(missing, "ClientID (OIDC_CLIENT_ID)")
	}
	if c.RedirectURL == "" {
		missing = append(missing, "RedirectURL (OIDC_REDIRECT_URL)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required auth config: %s", strings.Join(missing, ", "))
	}
	if u, err := url.Parse(c.RedirectURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("RedirectURL (OIDC_REDIRECT_URL) must be an absolute http(s) URL, got %q", c.RedirectURL)
	}
	if len(c.SessionSecretKey) < MinSecretKeyLength {
		return fmt.Errorf("SessionSecretKey (APP_SECRET_KEY) must be at least %d bytes", MinSecretKeyLength)
	}
	return nil
}

// Authenticator handles the OIDC login flow, session cookies and access control.
type Authenticator struct {
	config        Config
	oauth2Config  oauth2.Config
	verifier      *oidc.IDTokenVerifier
	secureCookies bool
}

// New validates cfg, discovers the OIDC provider and returns a ready Authenticator.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.SessionCookieName == "" {
		cfg.SessionCookieName = "session"
	}
	if cfg.StateCookieName == "" {
		cfg.StateCookieName = "oauth_state"
	}
	if cfg.SessionDuration == 0 {
		cfg.SessionDuration = 7 * 24 * time.Hour
	}

	provider, err := oidc.NewProvider(ctx, cfg.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	return &Authenticator{
		config: cfg,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "permissions"},
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		secureCookies: strings.HasPrefix(cfg.RedirectURL, "https://"),
	}, nil
}
