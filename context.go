package auth

import "context"

type contextKey struct{}

// ContextWithAuth returns a copy of ctx carrying info.
// Mainly useful for testing handlers without a real session.
func ContextWithAuth(ctx context.Context, info AuthInfo) context.Context {
	return context.WithValue(ctx, contextKey{}, info)
}

// FromContext returns the logged-in user stored by SessionMiddleware or RequirePermissions.
// It returns the zero AuthInfo and false for anonymous requests.
func FromContext(ctx context.Context) (AuthInfo, bool) {
	info, ok := ctx.Value(contextKey{}).(AuthInfo)
	if !ok || info.User == "" {
		return AuthInfo{}, false
	}
	return info, true
}
