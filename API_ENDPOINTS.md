# Aegis.Auth API Endpoints

This document shows the HTTP endpoints available in Aegis.Auth core and feature packages.

## Core Package Endpoints

### Email/Password Authentication

| Endpoint                    | Method | Description                           |
| --------------------------- | ------ | ------------------------------------- |
| `/auth/sign-up`             | POST   | Register new user with email/password |
| `/auth/sign-in`             | POST   | Sign in with email/password           |
| `/auth/sign-out`            | POST   | Sign out and invalidate session       |
| `/auth/verify-email`        | POST   | Verify email address                  |
| `/auth/resend-verification` | POST   | Resend verification email             |

**Example Request:**

```json
POST /auth/sign-in
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Example Response:**

```json
{
    "user": {
        "id": "uuid",
        "email": "user@example.com",
        "emailVerified": true
    },
    "session": {
        "id": "session-uuid",
        "expiresAt": "2026-03-10T00:00:00Z"
    }
}
```

---

## Passkeys Feature Package

Add with: `.AddPasskeys()`

### Passkey Endpoints

| Endpoint                         | Method | Description                                |
| -------------------------------- | ------ | ------------------------------------------ |
| `/auth/passkey/register/options` | POST   | Generate WebAuthn registration challenge   |
| `/auth/passkey/register/verify`  | POST   | Verify and store passkey credential        |
| `/auth/passkey/sign-in/options`  | POST   | Generate WebAuthn authentication challenge |
| `/auth/passkey/sign-in/verify`   | POST   | Verify passkey and create session          |

**Example Flow:**

1. **Start Registration:**

```json
POST /auth/passkey/register/options
{
  "userId": "user-uuid"
}
```

Response:

```json
{
  "challenge": "base64-challenge",
  "rp": { "name": "My App", "id": "example.com" },
  "user": { "id": "user-uuid", "name": "user@example.com" },
  "pubKeyCredParams": [...]
}
```

2. **Complete Registration:**

```json
POST /auth/passkey/register/verify
{
  "userId": "user-uuid",
  "attestation": { /* WebAuthn attestation response */ }
}
```

3. **Sign In (Options):**

```json
POST /auth/passkey/sign-in/options
{
  "userId": "user-uuid" // Optional - omit for usernameless flow
}
```

4. **Sign In (Verify):**

```json
POST /auth/passkey/sign-in/verify
{
  "assertion": { /* WebAuthn assertion response */ }
}
```

Response (same as email/password sign-in):

```json
{
    "user": { "id": "uuid", "email": "user@example.com" },
    "session": { "id": "session-uuid", "expiresAt": "..." }
}
```

---

## TOTP Feature Package (Future)

Add with: `.AddTotp()`

### TOTP Endpoints

| Endpoint             | Method | Description                      |
| -------------------- | ------ | -------------------------------- |
| `/auth/totp/setup`   | POST   | Generate TOTP secret and QR code |
| `/auth/totp/verify`  | POST   | Verify TOTP code and enable 2FA  |
| `/auth/totp/sign-in` | POST   | Sign in with TOTP second factor  |
| `/auth/totp/disable` | POST   | Disable TOTP for user            |

---

## OAuth/SSO Feature Package (Future)

Add with: `.AddOAuth(oauth => oauth.AddGoogle(...).AddGitHub(...))`

### OAuth Endpoints

| Endpoint                          | Method | Description                                |
| --------------------------------- | ------ | ------------------------------------------ |
| `/auth/oauth/{provider}`          | GET    | Initiate OAuth flow (redirect to provider) |
| `/auth/oauth/{provider}/callback` | GET    | Handle OAuth callback and create session   |
| `/auth/oauth/{provider}/link`     | POST   | Link OAuth account to existing user        |
| `/auth/oauth/{provider}/unlink`   | POST   | Unlink OAuth account                       |

**Example Flow:**

1. **Initiate OAuth:**

```
GET /auth/oauth/google
```

Redirects to Google consent screen.

2. **OAuth Callback:**

```
GET /auth/oauth/google/callback?code=auth-code&state=state-token
```

Automatically creates/links user and creates session.

---

## Shared Patterns

### Authentication

All endpoints that create sessions set an HTTP-only cookie:

```
Set-Cookie: aegis_session=token; HttpOnly; Secure; SameSite=Lax
```

### Error Responses

Consistent error format across all endpoints:

```json
{
    "error": {
        "code": "INVALID_CREDENTIALS",
        "message": "Email or password is incorrect"
    }
}
```

### CORS

Uses `AegisAuthOptions.TrustedOrigins` for CORS configuration.

---

## Key Design Points

1. **Independent Routes:** Each feature package owns its routes (`/auth/passkey/*`, `/auth/totp/*`)
2. **Consistent Responses:** All sign-in methods return `{ user, session }`
3. **Shared Session Logic:** All methods use `IAegisSessionService` internally
4. **No Core Modification:** Adding features doesn't change core endpoints
5. **RESTful Design:** Clear, predictable URL patterns

---

## Testing Endpoints

### With curl:

```bash
# Email/Password Sign In
curl -X POST https://example.com/auth/sign-in \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}' \
  -c cookies.txt

# Sign Out (using session cookie)
curl -X POST https://example.com/auth/sign-out \
  -b cookies.txt
```

### With JavaScript:

```javascript
// Email/Password Sign In
const response = await fetch("/auth/sign-in", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        email: "user@example.com",
        password: "password123",
    }),
    credentials: "include", // Important for cookies
});

const { user, session } = await response.json();
```

---

## Future Features

Potential feature packages in development:

- `Aegis.Auth.MagicLink` - Passwordless email links
- `Aegis.Auth.SMS` - SMS-based authentication
- `Aegis.Auth.Biometric` - Platform authenticators
- `Aegis.Auth.Organization` - Multi-tenant organization support

Each would follow the same pattern: Independent routes, shared session service, explicit DbContext entities.
