package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

// User is the identity and permissions of a logged-in user.
// The zero value represents an anonymous user with no permissions.
type User struct {
	Username    string // KTH ID, e.g. "turetek"
	Name        string // Full name, e.g. "Ture Teknolog"
	Email       string
	Permissions []Permission
}

// Permission is a Hive permission. Scope is empty for unscoped permissions
// and "*" for permissions that apply to every scope.
type Permission struct {
	ID    string `json:"id"`
	Scope string `json:"scope,omitempty"`
}

func (p Permission) String() string {
	if p.Scope == "" {
		return p.ID
	}
	return p.ID + ":" + p.Scope
}

// HasPermission reports whether the user has the given permission unscoped or
// with the wildcard scope "*", like Hive's own permission check.
func (u User) HasPermission(permission string) bool {
	return slices.ContainsFunc(u.Permissions, func(p Permission) bool {
		return p.ID == permission && (p.Scope == "" || p.Scope == "*")
	})
}

// HasPermissionScope reports whether the user has the given scoped permission
// for scope, either directly or through the wildcard scope "*".
func (u User) HasPermissionScope(permission, scope string) bool {
	return slices.ContainsFunc(u.Permissions, func(p Permission) bool {
		return p.ID == permission && p.Scope != "" && (p.Scope == scope || p.Scope == "*")
	})
}

// HasAnyPermission reports whether the user has at least one of the given permissions.
func (u User) HasAnyPermission(permissions ...string) bool {
	return slices.ContainsFunc(permissions, u.HasPermission)
}

// HasAllPermissions reports whether the user has every one of the given permissions.
func (u User) HasAllPermissions(permissions ...string) bool {
	for _, p := range permissions {
		if !u.HasPermission(p) {
			return false
		}
	}
	return true
}

type contextKey struct{}

// ContextWithUser returns a copy of ctx carrying user.
// Mainly useful for testing handlers without a real session.
func ContextWithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, contextKey{}, user)
}

// FromContext returns the logged-in user stored by SessionMiddleware or RequirePermissions.
// It returns the zero User and false for anonymous requests.
func FromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(contextKey{}).(User)
	if !ok || user.Username == "" {
		return User{}, false
	}
	return user, true
}

// parseIDTokenClaims expects permissions in Hive's format: [{"id": "admin", "scope": null}].
// The username is sub (the KTH ID); SSO sets preferred_username to the full name.
func parseIDTokenClaims(claimsJSON []byte) (User, error) {
	var raw struct {
		Sub         string       `json:"sub"`
		Name        string       `json:"name"`
		Email       string       `json:"email"`
		Permissions []Permission `json:"permissions"`
	}
	if err := json.Unmarshal(claimsJSON, &raw); err != nil {
		return User{}, fmt.Errorf("failed to unmarshal ID token claims: %w", err)
	}
	if raw.Sub == "" {
		return User{}, fmt.Errorf("ID token has no sub claim")
	}

	return User{Username: raw.Sub, Name: raw.Name, Email: raw.Email, Permissions: raw.Permissions}, nil
}
