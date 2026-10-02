package auth

import (
	"crypto/rand"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	stateTokenType = "oauth_state"
	stateLifetime  = 10 * time.Minute
)

// stateClaims carries the post-login destination through the OAuth round trip.
// The typ claim keeps session tokens from being accepted as state. State tokens
// are rejected as sessions because they have no subject.
type stateClaims struct {
	Type     string `json:"typ"`
	Nonce    string `json:"nonce"`
	ReturnTo string `json:"return_to"`
	jwt.RegisteredClaims
}

func (a *Authenticator) createState(returnTo string) (string, error) {
	return a.signToken(stateClaims{
		Type:     stateTokenType,
		Nonce:    rand.Text(),
		ReturnTo: returnTo,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(stateLifetime)),
		},
	})
}

func (a *Authenticator) parseState(token string) (returnTo string, err error) {
	var claims stateClaims
	if err := a.parseToken(token, &claims); err != nil {
		return "", err
	}
	if claims.Type != stateTokenType {
		return "", errors.New("not a state token")
	}
	return claims.ReturnTo, nil
}

// sanitizeReturnPath only allows local paths, preventing open redirects.
func sanitizeReturnPath(target string) string {
	if !strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "//") ||
		strings.HasPrefix(target, "/\\") || // browsers treat /\ like //
		strings.ContainsAny(target, "\r\n") {
		return "/"
	}
	return target
}
