package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testSecret = strings.Repeat("s", MinSecretKeyLength)

// newTestProvider serves a minimal OIDC discovery document so New works offline.
// Every other path returns the same document, so code exchanges against it fail.
func newTestProvider(t *testing.T) string {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func testConfig(t *testing.T) Config {
	return Config{
		ProviderURL:      newTestProvider(t),
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURL:      "http://localhost:3000/auth/callback",
		SessionSecretKey: testSecret,
	}
}

func newTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	a, err := New(context.Background(), testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func sessionCookie(t *testing.T, a *Authenticator, info AuthInfo) *http.Cookie {
	t.Helper()
	token, err := a.createSessionToken(info)
	if err != nil {
		t.Fatalf("createSessionToken: %v", err)
	}
	return &http.Cookie{Name: a.config.SessionCookieName, Value: token}
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestNewValidatesConfig(t *testing.T) {
	tests := map[string]func(*Config){
		"missing provider":      func(c *Config) { c.ProviderURL = "" },
		"missing client id":     func(c *Config) { c.ClientID = "" },
		"missing redirect url":  func(c *Config) { c.RedirectURL = "" },
		"relative redirect url": func(c *Config) { c.RedirectURL = "/auth/callback" },
		"short secret":          func(c *Config) { c.SessionSecretKey = "short" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			mutate(&cfg)
			if _, err := New(context.Background(), cfg); err == nil {
				t.Error("expected error")
			}
		})
	}

	a := newTestAuthenticator(t)
	if a.config.SessionCookieName != "session" || a.config.StateCookieName != "oauth_state" || a.config.SessionDuration != 7*24*time.Hour {
		t.Errorf("defaults not applied: %+v", a.config)
	}
	if a.secureCookies {
		t.Error("expected insecure cookies for http redirect URL")
	}
}

func TestLoginSetsStateCookie(t *testing.T) {
	a := newTestAuthenticator(t)
	mux := http.NewServeMux()
	a.MountAuthRoutes(mux)

	tests := map[string]string{
		"/admin?tab=1":      "/admin?tab=1",
		"//evil.example":    "/",
		"https://evil.test": "/",
	}
	for returnTo, want := range tests {
		rec := serve(mux, httptest.NewRequest("GET", LoginPath+"?return_to="+url.QueryEscape(returnTo), nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}

		cookies := rec.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != "oauth_state" || !cookies[0].HttpOnly {
			t.Fatalf("expected one HttpOnly state cookie, got %+v", cookies)
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Query().Get("state") != cookies[0].Value {
			t.Fatal("state in redirect does not match state cookie")
		}

		got, err := a.parseState(cookies[0].Value)
		if err != nil || got != want {
			t.Errorf("return_to %q: got %q (err %v), want %q", returnTo, got, err, want)
		}
	}
}

func TestCallbackValidatesState(t *testing.T) {
	a := newTestAuthenticator(t)
	mux := http.NewServeMux()
	a.MountAuthRoutes(mux)

	state, err := a.createState("/")
	if err != nil {
		t.Fatal(err)
	}
	session := sessionCookie(t, a, AuthInfo{User: "turetek"}).Value

	tests := []struct {
		name, state, cookie, code string
		wantCode                  int
		wantBody                  string
	}{
		{"missing cookie", state, "", "abc", http.StatusBadRequest, "Invalid or missing login state"},
		{"mismatched cookie", state, "other", "abc", http.StatusBadRequest, "Invalid or missing login state"},
		{"session token as state", session, session, "abc", http.StatusBadRequest, "expired"},
		{"cancelled login", state, state, "", http.StatusBadRequest, "cancelled"},
		{"valid state reaches code exchange", state, state, "abc", http.StatusInternalServerError, "Authentication failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{"state": {tt.state}}
			if tt.code != "" {
				q.Set("code", tt.code)
			}
			req := httptest.NewRequest("GET", CallbackPath+"?"+q.Encode(), nil)
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "oauth_state", Value: tt.cookie})
			}
			rec := serve(mux, req)
			if rec.Code != tt.wantCode || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("got %d %q, want %d containing %q", rec.Code, rec.Body.String(), tt.wantCode, tt.wantBody)
			}
		})
	}
}

func TestLogoutClearsSession(t *testing.T) {
	a := newTestAuthenticator(t)
	mux := http.NewServeMux()
	a.MountAuthRoutes(mux)

	rec := serve(mux, httptest.NewRequest("GET", LogoutPath, nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("expected 303 to /, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].MaxAge >= 0 {
		t.Errorf("expected session cookie to be cleared, got %+v", cookies)
	}
}

func TestCheckAuth(t *testing.T) {
	a := newTestAuthenticator(t)
	want := AuthInfo{User: "turetek", Email: "turetek@kth.se", Permissions: []string{"admin"}}

	expired := *a
	expired.config.SessionDuration = -time.Hour
	otherKey := *a
	otherKey.config.SessionSecretKey = strings.Repeat("x", MinSecretKeyLength)
	state, _ := a.createState("/")
	unsigned, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "turetek", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)

	invalid := map[string]string{
		"expired":     sessionCookie(t, &expired, want).Value,
		"wrong key":   sessionCookie(t, &otherKey, want).Value,
		"alg none":    unsigned,
		"state token": state,
		"garbage":     "not-a-jwt",
	}
	for name, token := range invalid {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: token})
		if _, ok := a.CheckAuth(req); ok {
			t.Errorf("%s: expected rejection", name)
		}
	}

	if _, ok := a.CheckAuth(httptest.NewRequest("GET", "/", nil)); ok {
		t.Error("expected no session without cookie")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(sessionCookie(t, a, want))
	got, ok := a.CheckAuth(req)
	if !ok || got.User != want.User || got.Email != want.Email || !got.HasPermission("admin") {
		t.Errorf("got %+v (ok=%v), want %+v", got, ok, want)
	}
}

func TestSessionMiddleware(t *testing.T) {
	a := newTestAuthenticator(t)
	var gotUser string
	var gotOK bool
	h := a.SessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := FromContext(r.Context())
		gotUser, gotOK = info.User, ok
	}))

	serve(h, httptest.NewRequest("GET", "/", nil))
	if gotOK {
		t.Error("anonymous request should not have a user")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(sessionCookie(t, a, AuthInfo{User: "turetek"}))
	serve(h, req)
	if !gotOK || gotUser != "turetek" {
		t.Errorf("expected turetek in context, got %q (ok=%v)", gotUser, gotOK)
	}
}

func TestRequirePermissions(t *testing.T) {
	a := newTestAuthenticator(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, loggedIn := FromContext(r.Context()); !loggedIn {
			t.Error("protected handler ran without user in context")
		}
	})
	admin := sessionCookie(t, a, AuthInfo{User: "turetek", Permissions: []string{"admin"}})
	viewer := sessionCookie(t, a, AuthInfo{User: "diadat", Permissions: []string{"view-all"}})

	tests := []struct {
		name         string
		handler      http.Handler
		method, path string
		cookie       *http.Cookie
		wantCode     int
		wantLocation string
	}{
		{"anonymous GET redirects", a.RequirePermissions("admin")(ok), "GET", "/admin?tab=1", nil, http.StatusFound, "/login?return_to=%2Fadmin%3Ftab%3D1"},
		{"anonymous GET of root", a.RequireAuth(ok), "GET", "/", nil, http.StatusFound, "/login"},
		{"anonymous POST is 401", a.RequirePermissions("admin")(ok), "POST", "/admin/items", nil, http.StatusUnauthorized, ""},
		{"missing permission is 403", a.RequirePermissions("admin")(ok), "GET", "/admin", viewer, http.StatusForbidden, ""},
		{"any listed permission passes", a.RequirePermissions("admin", "view-all")(ok), "GET", "/admin", viewer, http.StatusOK, ""},
		{"admin passes", a.RequirePermissions("admin")(ok), "POST", "/admin/items", admin, http.StatusOK, ""},
		{"RequireAuth passes any user", a.RequireAuth(ok), "GET", "/", viewer, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			rec := serve(tt.handler, req)
			if rec.Code != tt.wantCode || rec.Header().Get("Location") != tt.wantLocation {
				t.Errorf("got %d %q, want %d %q", rec.Code, rec.Header().Get("Location"), tt.wantCode, tt.wantLocation)
			}
		})
	}
}

func TestSanitizeReturnURL(t *testing.T) {
	tests := map[string]string{
		"":                     "/",
		"/":                    "/",
		"/admin?x=1":           "/admin?x=1",
		"admin":                "/",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"/ok\r\nSet-Cookie: x": "/",
	}
	for in, want := range tests {
		if got := sanitizeReturnURL(in); got != want {
			t.Errorf("sanitizeReturnURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIDTokenClaims(t *testing.T) {
	tests := []struct {
		name      string
		claims    string
		wantUser  string
		wantPerms []string
		wantErr   bool
	}{
		{"string permissions", `{"preferred_username":"diadat","email":"diadat@kth.se","permissions":["view-all"]}`, "diadat", []string{"view-all"}, false},
		{"object permissions", `{"preferred_username":"turetek","permissions":[{"id":"admin","scope":""},{"id":"editor"}]}`, "turetek", []string{"admin", "editor"}, false},
		{"null permissions", `{"preferred_username":"turetek","permissions":null}`, "turetek", nil, false},
		{"falls back to email", `{"email":"turetek@kth.se","sub":"x"}`, "turetek@kth.se", nil, false},
		{"falls back to sub", `{"sub":"kth-id-1"}`, "kth-id-1", nil, false},
		{"no user", `{"permissions":["admin"]}`, "", nil, true},
		{"bad permissions", `{"sub":"x","permissions":"admin"}`, "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseIDTokenClaims([]byte(tt.claims))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if info.User != tt.wantUser || strings.Join(info.Permissions, ",") != strings.Join(tt.wantPerms, ",") {
				t.Errorf("got %+v, want user %q perms %v", info, tt.wantUser, tt.wantPerms)
			}
		})
	}
}

func TestAuthInfoPermissions(t *testing.T) {
	info := AuthInfo{User: "turetek", Permissions: []string{"admin", "editor"}}

	if !info.HasPermission("admin") || info.HasPermission("viewer") {
		t.Error("HasPermission")
	}
	if !info.HasAnyPermission("viewer", "editor") || info.HasAnyPermission("viewer", "root") || info.HasAnyPermission() {
		t.Error("HasAnyPermission")
	}
	if !info.HasAllPermissions("admin", "editor") || info.HasAllPermissions("admin", "root") {
		t.Error("HasAllPermissions")
	}
	if (AuthInfo{}).HasAnyPermission("admin") {
		t.Error("anonymous user should have no permissions")
	}
}

func TestFromContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Error("empty context should not have a user")
	}
	if _, ok := FromContext(ContextWithAuth(context.Background(), AuthInfo{})); ok {
		t.Error("AuthInfo without user should not count as logged in")
	}
	info, ok := FromContext(ContextWithAuth(context.Background(), AuthInfo{User: "turetek"}))
	if !ok || info.User != "turetek" {
		t.Errorf("got %+v (ok=%v)", info, ok)
	}
}
