package auth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type sessionClaims struct {
	Email       string   `json:"email,omitempty"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// CheckAuth returns the user of the request's session cookie, if it holds a valid session.
func (a *Authenticator) CheckAuth(r *http.Request) (AuthInfo, bool) {
	cookie, err := r.Cookie(a.config.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return AuthInfo{}, false
	}

	var claims sessionClaims
	if err := a.parseToken(cookie.Value, &claims); err != nil || claims.Subject == "" {
		return AuthInfo{}, false
	}

	return AuthInfo{
		User:        claims.Subject,
		Email:       claims.Email,
		Permissions: claims.Permissions,
	}, true
}

func (a *Authenticator) createSessionToken(info AuthInfo) (string, error) {
	now := time.Now()
	return a.signToken(sessionClaims{
		Email:       info.Email,
		Permissions: info.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   info.User,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(a.config.SessionDuration)),
		},
	})
}
