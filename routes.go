package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Paths registered by MountAuthRoutes. Config.RedirectURL must route to CallbackPath.
const (
	LoginPath    = "/login"
	CallbackPath = "/auth/callback"
	LogoutPath   = "/logout"
)

// MountAuthRoutes registers the login, callback and logout handlers on mux.
func (a *Authenticator) MountAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+LoginPath, a.handleLogin)
	mux.HandleFunc("GET "+CallbackPath, a.handleCallback)
	mux.HandleFunc("GET "+LogoutPath, a.handleLogout)
}

func (a *Authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := a.createState(sanitizeReturnPath(r.URL.Query().Get("return_to")))
	if err != nil {
		slog.Error("failed to create OAuth state", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	a.setCookie(w, a.config.StateCookieName, state, int(stateLifetime.Seconds()))
	http.Redirect(w, r, a.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	state := query.Get("state")

	// The cookie binds the state to this browser; without it a valid state could be replayed (login CSRF).
	cookie, err := r.Cookie(a.config.StateCookieName)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "Invalid or missing login state, please try logging in again", http.StatusBadRequest)
		return
	}
	returnTo, err := a.parseState(state)
	if err != nil {
		http.Error(w, "Login state expired, please try logging in again", http.StatusBadRequest)
		return
	}
	a.setCookie(w, a.config.StateCookieName, "", -1)

	// Missing when the user cancels or the provider rejects the request.
	code := query.Get("code")
	if code == "" {
		description := query.Get("error_description")
		slog.Warn("login rejected by SSO", "error", query.Get("error"), "description", description)
		msg := "Login was cancelled or denied"
		if description != "" {
			msg += ": " + description
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	info, err := a.exchangeCode(r.Context(), code)
	if err != nil {
		slog.Error("OIDC code exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	token, err := a.createSessionToken(info)
	if err != nil {
		slog.Error("failed to create session token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	a.setCookie(w, a.config.SessionCookieName, token, int(a.config.SessionDuration.Seconds()))
	// returnTo was sanitized in handleLogin and is protected by the state signature.
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// Only clears the local session; the user stays logged in at the SSO provider.
func (a *Authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.setCookie(w, a.config.SessionCookieName, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// exchangeCode trades an authorization code for a verified ID token and returns its user.
func (a *Authenticator) exchangeCode(ctx context.Context, code string) (User, error) {
	token, err := a.oauth2Config.Exchange(oidc.ClientContext(ctx, a.httpClient), code)
	if err != nil {
		return User{}, fmt.Errorf("token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return User{}, fmt.Errorf("token response has no id_token")
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return User{}, fmt.Errorf("failed to verify id_token: %w", err)
	}

	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return User{}, fmt.Errorf("failed to read id_token claims: %w", err)
	}
	return parseIDTokenClaims(claims)
}
