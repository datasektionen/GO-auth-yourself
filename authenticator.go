// Package auth provides OIDC login, signed session cookies and permission
// middleware for Datasektionen systems.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// MinSecretKeyLength is the minimum accepted length of Config.SecretKey in bytes.
const MinSecretKeyLength = 32

// providerTimeout bounds every request to the SSO: discovery, key fetches and code exchange.
const providerTimeout = 10 * time.Second

// Config configures an Authenticator.
type Config struct {
	ProviderURL       string        // OIDC provider URL, e.g. "https://sso.datasektionen.se/op"
	ClientID          string        // OAuth2 client ID
	ClientSecret      string        // OAuth2 client secret
	RedirectURL       string        // Absolute URL that routes to CallbackPath
	SecretKey         string        // Signs session and state tokens, at least MinSecretKeyLength bytes
	SessionCookieName string        // Default "session"
	StateCookieName   string        // Default "oauth_state"
	SessionDuration   time.Duration // Default 7 days
}

// ConfigFromEnv reads OIDC_PROVIDER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
// OIDC_REDIRECT_URL and APP_SECRET_KEY. Validation happens in New.
func ConfigFromEnv() Config {
	return Config{
		ProviderURL:  os.Getenv("OIDC_PROVIDER"),
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
		SecretKey:    os.Getenv("APP_SECRET_KEY"),
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
	if c.ClientSecret == "" {
		missing = append(missing, "ClientSecret (OIDC_CLIENT_SECRET)")
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
	if len(c.SecretKey) < MinSecretKeyLength {
		return fmt.Errorf("SecretKey (APP_SECRET_KEY) must be at least %d bytes", MinSecretKeyLength)
	}
	return nil
}

// Authenticator handles the OIDC login flow, session cookies and access control.
type Authenticator struct {
	config        Config
	oauth2Config  oauth2.Config
	verifier      *oidc.IDTokenVerifier
	httpClient    *http.Client
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

	httpClient := &http.Client{Timeout: providerTimeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), cfg.ProviderURL)
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
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "permissions"},
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		httpClient:    httpClient,
		secureCookies: strings.HasPrefix(cfg.RedirectURL, "https://"),
	}, nil
}

func (a *Authenticator) signToken(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(a.config.SecretKey))
}

func (a *Authenticator) parseToken(token string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(token, claims,
		func(*jwt.Token) (any, error) { return []byte(a.config.SecretKey), nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	return err
}

func (a *Authenticator) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}
