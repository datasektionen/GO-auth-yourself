package auth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Permissions are a snapshot from login; Hive changes apply on next login.
type sessionClaims struct {
	Email       string       `json:"email,omitempty"`
	Permissions []Permission `json:"permissions"`
	jwt.RegisteredClaims
}

// readSession returns the user of the request's session cookie, if it holds a valid session.
func (a *Authenticator) readSession(r *http.Request) (User, bool) {
	cookie, err := r.Cookie(a.config.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return User{}, false
	}

	var claims sessionClaims
	if err := a.parseToken(cookie.Value, &claims); err != nil || claims.Subject == "" {
		return User{}, false
	}

	return User{
		Username:    claims.Subject,
		Email:       claims.Email,
		Permissions: claims.Permissions,
	}, true
}

func (a *Authenticator) createSessionToken(info User) (string, error) {
	now := time.Now()
	return a.signToken(sessionClaims{
		Email:       info.Email,
		Permissions: info.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   info.Username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(a.config.SessionDuration)),
		},
	})
}
