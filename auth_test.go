package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testSecret = strings.Repeat("s", MinSecretKeyLength)

const testCode = "valid-code"

// Claims the test provider puts in every ID token, shaped like sso.datasektionen.se's.
var testIDClaims = map[string]any{
	"sub":                "turetek",
	"preferred_username": "Ture Teknolog",
	"name":               "Ture Teknolog",
	"email":              "turetek@kth.se",
	"permissions":        []map[string]any{{"id": "admin", "scope": nil}, {"id": "write", "scope": "/central"}},
}

var testSigningKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// newTestProvider runs a minimal OIDC provider that exchanges testCode for a
// signed ID token with testIDClaims and rejects every other code.
func newTestProvider(t *testing.T) string {
	t.Helper()
	key := testSigningKey()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != testCode {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		claims := jwt.MapClaims{"iss": srv.URL, "aud": "client-id", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range testIDClaims {
			claims[k] = v
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test"
		idToken, err := token.SignedString(key)
		if err != nil {
			t.Errorf("sign ID token: %v", err)
		}
		writeJSON(w, map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
	})
	return srv.URL
}

func testConfig(t *testing.T) Config {
	return Config{
		ProviderURL:  newTestProvider(t),
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://localhost:3000/auth/callback",
		SecretKey:    testSecret,
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

func sessionCookie(t *testing.T, a *Authenticator, info User) *http.Cookie {
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
		"missing client secret": func(c *Config) { c.ClientSecret = "" },
		"missing redirect url":  func(c *Config) { c.RedirectURL = "" },
		"relative redirect url": func(c *Config) { c.RedirectURL = "/auth/callback" },
		"short secret":          func(c *Config) { c.SecretKey = "short" },
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
	session := sessionCookie(t, a, User{Username: "turetek"}).Value

	tests := []struct {
		name, state, cookie, code, errDescription string
		wantCode                                  int
		wantBody                                  string
	}{
		{"missing cookie", state, "", "abc", "", http.StatusBadRequest, "Invalid or missing login state"},
		{"mismatched cookie", state, "other", "abc", "", http.StatusBadRequest, "Invalid or missing login state"},
		{"session token as state", session, session, "abc", "", http.StatusBadRequest, "expired"},
		{"cancelled login", state, state, "", "", http.StatusBadRequest, "cancelled"},
		{"SSO error is shown", state, state, "", "User is not allowed", http.StatusBadRequest, "User is not allowed"},
		{"code rejected by SSO", state, state, "abc", "", http.StatusInternalServerError, "Authentication failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{"state": {tt.state}}
			if tt.code != "" {
				q.Set("code", tt.code)
			}
			if tt.errDescription != "" {
				q.Set("error", "access_denied")
				q.Set("error_description", tt.errDescription)
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

func TestCallbackLogsIn(t *testing.T) {
	a := newTestAuthenticator(t)
	mux := http.NewServeMux()
	a.MountAuthRoutes(mux)

	state, err := a.createState("/admin")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", CallbackPath+"?"+url.Values{"state": {state}, "code": {testCode}}.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: state})
	rec := serve(mux, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin" {
		t.Fatalf("expected 303 to /admin, got %d %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}

	next := httptest.NewRequest("GET", "/admin", nil)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "oauth_state" && c.MaxAge >= 0 {
			t.Error("state cookie was not cleared")
		}
		if c.Name == "session" {
			next.AddCookie(c)
		}
	}
	user, ok := a.readSession(next)
	want := User{
		Username:    "turetek",
		Name:        "Ture Teknolog",
		Email:       "turetek@kth.se",
		Permissions: []Permission{{ID: "admin"}, {ID: "write", Scope: "/central"}},
	}
	if !ok || user.Username != want.Username || user.Name != want.Name || user.Email != want.Email || !slices.Equal(user.Permissions, want.Permissions) {
		t.Errorf("session user = %+v (ok=%v), want %+v", user, ok, want)
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

func TestReadSession(t *testing.T) {
	a := newTestAuthenticator(t)
	want := User{Username: "turetek", Name: "Ture Teknolog", Email: "turetek@kth.se", Permissions: []Permission{{ID: "admin"}}}

	expired := *a
	expired.config.SessionDuration = -time.Hour
	otherKey := *a
	otherKey.config.SecretKey = strings.Repeat("x", MinSecretKeyLength)
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
		if _, ok := a.readSession(req); ok {
			t.Errorf("%s: expected rejection", name)
		}
	}

	if _, ok := a.readSession(httptest.NewRequest("GET", "/", nil)); ok {
		t.Error("expected no session without cookie")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(sessionCookie(t, a, want))
	got, ok := a.readSession(req)
	if !ok || got.Username != want.Username || got.Name != want.Name || got.Email != want.Email || !got.HasPermission("admin") {
		t.Errorf("got %+v (ok=%v), want %+v", got, ok, want)
	}
}

func TestSessionMiddleware(t *testing.T) {
	a := newTestAuthenticator(t)
	var gotUser string
	var gotOK bool
	h := a.SessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := FromContext(r.Context())
		gotUser, gotOK = info.Username, ok
	}))

	serve(h, httptest.NewRequest("GET", "/", nil))
	if gotOK {
		t.Error("anonymous request should not have a user")
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(sessionCookie(t, a, User{Username: "turetek"}))
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
	admin := sessionCookie(t, a, User{Username: "turetek", Permissions: []Permission{{ID: "admin"}}})
	viewer := sessionCookie(t, a, User{Username: "diadat", Permissions: []Permission{{ID: "view-all"}}})

	tests := []struct {
		name         string
		handler      http.Handler
		method, path string
		cookie       *http.Cookie
		wantCode     int
		wantLocation string
	}{
		{"anonymous GET redirects", a.RequirePermissions("admin")(ok), "GET", "/admin?tab=1", nil, http.StatusFound, "/login?return_to=%2Fadmin%3Ftab%3D1"},
		{"anonymous GET of root", a.RequireLogin(ok), "GET", "/", nil, http.StatusFound, "/login"},
		{"anonymous POST is 401", a.RequirePermissions("admin")(ok), "POST", "/admin/items", nil, http.StatusUnauthorized, ""},
		{"missing permission is 403", a.RequirePermissions("admin")(ok), "GET", "/admin", viewer, http.StatusForbidden, ""},
		{"any listed permission passes", a.RequirePermissions("admin", "view-all")(ok), "GET", "/admin", viewer, http.StatusOK, ""},
		{"admin passes", a.RequirePermissions("admin")(ok), "POST", "/admin/items", admin, http.StatusOK, ""},
		{"RequireLogin passes any user", a.RequireLogin(ok), "GET", "/", viewer, http.StatusOK, ""},
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

func TestSanitizeReturnPath(t *testing.T) {
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
		if got := sanitizeReturnPath(in); got != want {
			t.Errorf("sanitizeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIDTokenClaims(t *testing.T) {
	tests := []struct {
		name      string
		claims    string
		wantUser  string
		wantPerms []Permission
		wantErr   bool
	}{
		{"hive permissions", `{"sub":"turetek","email":"turetek@kth.se","permissions":[{"id":"admin","scope":null},{"id":"write","scope":"/central"}]}`, "turetek", []Permission{{ID: "admin"}, {ID: "write", Scope: "/central"}}, false},
		{"null permissions", `{"sub":"turetek","permissions":null}`, "turetek", nil, false},
		{"ignores preferred_username", `{"sub":"turetek","preferred_username":"Ture Teknolog"}`, "turetek", nil, false},
		{"no sub", `{"preferred_username":"turetek","email":"turetek@kth.se"}`, "", nil, true},
		{"string permissions", `{"sub":"x","permissions":["admin"]}`, "", nil, true},
		{"bad permissions", `{"sub":"x","permissions":"admin"}`, "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseIDTokenClaims([]byte(tt.claims))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if info.Username != tt.wantUser || !slices.Equal(info.Permissions, tt.wantPerms) {
				t.Errorf("got %+v, want user %q perms %v", info, tt.wantUser, tt.wantPerms)
			}
		})
	}
}

func TestUserPermissions(t *testing.T) {
	info := User{Username: "turetek", Permissions: []Permission{
		{ID: "admin"},
		{ID: "editor"},
		{ID: "attest", Scope: "*"},
		{ID: "write", Scope: "/central"},
	}}

	if !info.HasPermission("admin") || !info.HasPermission("attest") || info.HasPermission("write") || info.HasPermission("viewer") {
		t.Error("HasPermission")
	}
	if !info.HasPermissionScope("write", "/central") || !info.HasPermissionScope("attest", "/any") ||
		info.HasPermissionScope("write", "/other") || info.HasPermissionScope("admin", "/central") {
		t.Error("HasPermissionScope")
	}
	if !info.HasAnyPermission("viewer", "editor") || info.HasAnyPermission("viewer", "root") || info.HasAnyPermission() {
		t.Error("HasAnyPermission")
	}
	if !info.HasAllPermissions("admin", "editor") || info.HasAllPermissions("admin", "root") {
		t.Error("HasAllPermissions")
	}
	if (User{}).HasAnyPermission("admin") {
		t.Error("anonymous user should have no permissions")
	}
	if got := (Permission{ID: "write", Scope: "/central"}).String(); got != "write:/central" {
		t.Errorf("String() = %q", got)
	}
}

func TestFromContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Error("empty context should not have a user")
	}
	if _, ok := FromContext(ContextWithUser(context.Background(), User{})); ok {
		t.Error("User without username should not count as logged in")
	}
	info, ok := FromContext(ContextWithUser(context.Background(), User{Username: "turetek"}))
	if !ok || info.Username != "turetek" {
		t.Errorf("got %+v (ok=%v)", info, ok)
	}
}
