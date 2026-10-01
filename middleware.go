package auth

import (
	"log/slog"
	"net/http"
	"net/url"
)

// SessionMiddleware adds the logged-in user to the request context when the
// request has a valid session. Anonymous requests pass through unchanged.
func (a *Authenticator) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if info, ok := a.CheckAuth(r); ok {
			r = r.WithContext(ContextWithAuth(r.Context(), info))
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuth only lets logged-in users through. See RequirePermissions.
func (a *Authenticator) RequireAuth(next http.Handler) http.Handler {
	return a.RequirePermissions()(next)
}

// RequirePermissions only lets through logged-in users holding at least one of perms.
// Anonymous GET/HEAD requests are redirected to LoginPath, other anonymous requests
// get 401, and logged-in users lacking permissions get 403.
func (a *Authenticator) RequirePermissions(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, ok := a.CheckAuth(r)
			if !ok {
				denyAnonymous(w, r)
				return
			}
			if len(perms) > 0 && !info.HasAnyPermission(perms...) {
				slog.Warn("access denied: missing permissions", "user", info.User, "required", perms, "path", r.URL.Path)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithAuth(r.Context(), info)))
		})
	}
}

// Redirecting a POST to the login page would silently drop its body, so only safe methods redirect.
func denyAnonymous(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	loginURL := LoginPath
	if ret := sanitizeReturnURL(r.URL.RequestURI()); ret != "/" {
		loginURL += "?return_to=" + url.QueryEscape(ret)
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}
