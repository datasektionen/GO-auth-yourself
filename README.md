# GO-auth-yourself

OIDC login, signed session cookies and permission middleware for Datasektionen systems.

```sh
go get github.com/datasektionen/GO-auth-yourself
```

The package is named `auth`. Import it with an explicit alias so it reads clearly:

```go
import auth "github.com/datasektionen/GO-auth-yourself"
```

## Quick start

```go
func main() {
    authenticator, err := auth.New(context.Background(), auth.ConfigFromEnv())
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    authenticator.MountAuthRoutes(mux) // GET /login, /auth/callback, /logout

    // Public page: the user is available if logged in.
    mux.Handle("GET /{$}", authenticator.SessionMiddleware(http.HandlerFunc(home)))

    // Any logged-in user.
    mux.Handle("GET /profile", authenticator.RequireAuth(http.HandlerFunc(profile)))

    // Users with at least one of the listed permissions.
    requireAdmin := authenticator.RequirePermissions("admin")
    mux.Handle("GET /admin", requireAdmin(http.HandlerFunc(admin)))
    mux.Handle("POST /admin/items", requireAdmin(http.HandlerFunc(createItem)))

    log.Fatal(http.ListenAndServe(":3000", mux))
}

func home(w http.ResponseWriter, r *http.Request) {
    if info, ok := auth.FromContext(r.Context()); ok {
        fmt.Fprintf(w, "Hello %s, you have %v", info.User, info.Permissions)
        return
    }
    fmt.Fprint(w, `Hello guest! <a href="/login">Log in</a>`)
}
```

## Configuration

`ConfigFromEnv` reads the standard environment variables. `New` fails at startup if anything required is missing.

| Variable             | `Config` field     | Notes                                                      |
| -------------------- | ------------------ | ---------------------------------------------------------- |
| `OIDC_PROVIDER`      | `ProviderURL`      | e.g. `https://sso.datasektionen.se/op`                     |
| `OIDC_CLIENT_ID`     | `ClientID`         | Required                                                   |
| `OIDC_CLIENT_SECRET` | `ClientSecret`     |                                                            |
| `OIDC_REDIRECT_URL`  | `RedirectURL`      | Absolute URL that routes to `/auth/callback`               |
| `APP_SECRET_KEY`     | `SessionSecretKey` | At least 32 bytes. Generate with `openssl rand -base64 48` |

Optional fields: `SessionCookieName` (default `session`), `StateCookieName` (default `oauth_state`) and `SessionDuration` (default 7 days).

Cookies get the `Secure` flag when `RedirectURL` uses `https://`.

## Behaviour

| Situation                                      | Response                                    |
| ---------------------------------------------- | ------------------------------------------- |
| Anonymous `GET`/`HEAD` to a protected route    | `302` to `/login?return_to=<original path>` |
| Anonymous request with any other method        | `401 Unauthorized`                          |
| Logged in but missing all required permissions | `403 Forbidden`                             |
| `SessionMiddleware` with no or invalid session | Passes through anonymously                  |

- Permissions are read from the ID token's `permissions` claim (requested via the `permissions` scope). Both `["admin"]` and Hive-style `[{"id": "admin"}]` are supported.
- Permissions are stored in the session cookie, so changes in Hive apply on the user's next login.
- `return_to` only accepts local paths, so it cannot be used for open redirects.
- The OAuth `state` is bound to the browser with a cookie, which prevents login CSRF.
- PKCE is not used, since `sso.datasektionen.se` does not advertise `code_challenge_methods_supported`. The client secret protects the code exchange instead.
- Only the session cookie is accepted; there is no `Authorization: Bearer` support.

## Templates

Pass the `AuthInfo` to your templates and call its methods directly:

```go
info, loggedIn := auth.FromContext(r.Context())
tmpl.ExecuteTemplate(w, "index.gohtml", map[string]any{"auth": info, "loggedIn": loggedIn})
```

```html
{{if .auth.HasPermission "admin"}}<a href="/admin">Admin</a>{{end}} {{if
.auth.HasAnyPermission "admin" "view-all"}}...{{end}}
```

The zero `AuthInfo` (anonymous user) has no permissions, so these work without extra checks.

## Testing your handlers

Use `ContextWithAuth` to run handlers as a specific user without a real login:

```go
req := httptest.NewRequest("GET", "/admin", nil)
req = req.WithContext(auth.ContextWithAuth(req.Context(), auth.AuthInfo{
    User:        "turetek",
    Permissions: []string{"admin"},
}))
```

## Local development next to an application

Point your application at a local checkout:

```sh
go mod edit -replace github.com/datasektionen/GO-auth-yourself=../GO-auth-yourself
```

Remove the `replace` before building production images, since the sibling directory is not part of the Docker build context. With Docker Compose, pass the folder via `additional_contexts`:

```yaml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.dev
      additional_contexts:
        auth: ../GO-auth-yourself
```

```dockerfile
COPY --from=auth . /GO-auth-yourself
```
