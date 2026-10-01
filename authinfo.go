package auth

import (
	"encoding/json"
	"fmt"
	"slices"
)

// AuthInfo is the identity and permissions of a logged-in user.
// The zero value represents an anonymous user with no permissions.
type AuthInfo struct {
	User        string   `json:"user"`
	Email       string   `json:"email"`
	Permissions []string `json:"permissions"`
}

// HasPermission reports whether the user has the given permission.
func (a AuthInfo) HasPermission(permission string) bool {
	return slices.Contains(a.Permissions, permission)
}

// HasAnyPermission reports whether the user has at least one of the given permissions.
func (a AuthInfo) HasAnyPermission(permissions ...string) bool {
	return slices.ContainsFunc(permissions, a.HasPermission)
}

// HasAllPermissions reports whether the user has every one of the given permissions.
func (a AuthInfo) HasAllPermissions(permissions ...string) bool {
	for _, p := range permissions {
		if !a.HasPermission(p) {
			return false
		}
	}
	return true
}

// parseIDTokenClaims accepts permissions both as strings (["admin"]) and as
// Hive/Nyckeln objects ([{"id": "admin"}]).
func parseIDTokenClaims(claimsJSON []byte) (AuthInfo, error) {
	var raw struct {
		PreferredUsername string          `json:"preferred_username"`
		Email             string          `json:"email"`
		Sub               string          `json:"sub"`
		Permissions       json.RawMessage `json:"permissions"`
	}
	if err := json.Unmarshal(claimsJSON, &raw); err != nil {
		return AuthInfo{}, fmt.Errorf("failed to unmarshal ID token claims: %w", err)
	}

	var permissions []string
	if len(raw.Permissions) > 0 {
		var strPerms []string
		var objPerms []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw.Permissions, &strPerms); err == nil {
			permissions = strPerms
		} else if err := json.Unmarshal(raw.Permissions, &objPerms); err == nil {
			for _, p := range objPerms {
				if p.ID != "" {
					permissions = append(permissions, p.ID)
				}
			}
		} else {
			return AuthInfo{}, fmt.Errorf("unsupported permissions claim format: %w", err)
		}
	}

	user := raw.PreferredUsername
	if user == "" {
		user = raw.Email
	}
	if user == "" {
		user = raw.Sub
	}
	if user == "" {
		return AuthInfo{}, fmt.Errorf("ID token has no user identifier")
	}

	return AuthInfo{User: user, Email: raw.Email, Permissions: permissions}, nil
}
