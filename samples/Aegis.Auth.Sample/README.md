# Aegis.Auth Sample API

This is a sample ASP.NET Core Web API project that demonstrates how to use the Aegis.Auth core library together with the Aegis.Auth.Http endpoint package.

## Features

- ✅ Email/Password authentication
- ✅ Minimal API auth endpoints mapped from `Aegis.Auth.Http`
- ✅ Secure session management with signed cookies
- ✅ Cookie-based session caching
- ✅ Business domain example (`Projects` + `ProjectTasks`) tied to authenticated user
- ✅ SQLite database for realistic local persistence
- ✅ Strongly typed app-specific user extension (`AppUser.IsSpecial`)
- ✅ Controller protection example via `[AegisAuthorize]`
- ✅ Minimal API protection example via `.RequireAegisAuth()`
- ✅ Pre-seeded test user

## Test Credentials

```
Email: test@example.com
Password: Password123!
```

## Running the Application

```bash
cd samples/Aegis.Auth.Sample
dotnet run
```

The API will start on `http://localhost:5000` (and `https://localhost:5001` for HTTPS).

## Available Endpoints

### Health Check

```http
GET /api/health
```

Returns the health status and configuration of the API.

```http
GET /api/health/users
```

Lists all users in the database with their accounts and sessions.

### Sign In

```http
POST /api/auth/sign-in/email
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "Password123!",
  "rememberMe": true,
  "callback": null
}
```

### Sign Up

```http
POST /api/auth/sign-up/email
Content-Type: application/json

{
  "name": "New Sample User",
  "email": "new-user@example.com",
  "password": "Password123!",
  "image": "https://example.com/avatar.png",
  "callback": null
}
```

### Business Endpoints (Authenticated)

```http
GET /api/projects/my
```

Returns projects owned by the currently authenticated user.
This controller is protected by `[AegisAuthorize]` and reads `HttpContext.GetAegisAuthContext()`.

```http
GET /api/projects/my/workspace
```

Returns tier/limits/usage from app business logic powered by the typed custom user field (`AppUser.IsSpecial`).

```http
POST /api/projects
Content-Type: application/json

{
  "name": "Launch Marketing Site",
  "description": "Coordinate tasks for the landing page release."
}
```

```http
GET /api/projects/{projectId}/tasks
```

```http
POST /api/projects/{projectId}/tasks
Content-Type: application/json

{
  "title": "Ship first public beta"
}
```

### Custom Minimal API Behind Authentication

```http
GET /api/demo/me
```

Demonstrates user-defined minimal APIs protected with `.RequireAegisAuth()`.

## Testing with curl

### Health Check

```bash
curl http://localhost:5000/api/health
```

### Sign In

```bash
curl -X POST http://localhost:5000/api/auth/sign-in/email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Password123!",
    "rememberMe": true
  }' \
  -c cookies.txt \
  -v
```

The `-c cookies.txt` flag saves the session cookies to a file, and `-v` shows verbose output including headers.

### Sign Up

```bash
curl -X POST http://localhost:5000/api/auth/sign-up/email \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Sample User",
    "email": "new-user@example.com",
    "password": "Password123!",
    "image": "https://example.com/avatar.png",
    "callback": null
  }' \
  -c cookies.txt \
  -v
```

Use a unique email if you run the same request more than once, or delete the local `.db` file to reset state.

### Authenticated Business Flow

```bash
# 1) Sign in and store cookies
curl -X POST http://localhost:5000/api/auth/sign-in/email \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Password123!","rememberMe":true}' \
  -c cookies.txt

# 2) Read seeded business data for signed-in user
curl http://localhost:5000/api/projects/my -b cookies.txt

# 3) Read tier/limits for the current user
curl http://localhost:5000/api/projects/my/workspace -b cookies.txt

# 4) Read current auth context through a protected minimal API
curl http://localhost:5000/api/demo/me -b cookies.txt

# 5) Create a project
curl -X POST http://localhost:5000/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"Aegis Demo","description":"Show auth-powered business behavior"}' \
  -b cookies.txt
```

## Configuration

The Aegis.Auth configuration and endpoint mapping are in `Program.cs`:

- **Secret**: Used for signing cookies and tokens
- **Email/Password**: Enabled with verification optional for testing
- **Session**: 1-hour expiration with 5-minute cookie cache
- **Cookie Cache**: Enabled to reduce database lookups
- **Database**: SQLite (`ConnectionStrings:DefaultConnection`)

Auth endpoints are mapped explicitly:

```csharp
app.MapAegisAuthEndpoints(options =>
{
  builder.Configuration.GetSection("AegisHttp").Bind(options);
  options.MapEmailSignIn = true;
  options.MapEmailSignUp = true;
  options.MapSignOut = true;
});
```

This lets you remove routes entirely (for example, no sign-up endpoint in production) instead of returning feature-disabled responses.

## Architecture

- **Data/SampleAuthDbContext.cs**: EF Core DbContext implementing `IAuthDbContext`
- **Data/DataSeeder.cs**: Seeds test data into the SQLite database
- **Controllers/HealthController.cs**: Health check and diagnostics endpoint
- **Controllers/ProjectsController.cs**: Business API orchestrating authenticated workspace operations
- **Services/ProjectWorkspaceService.cs**: Business workflow service with tier limits based on `AppUser.IsSpecial`
- **Entities/AppUser.cs**: App-owned strongly typed extension of `Aegis.Auth.Entities.User`
- **Program.cs**: Application configuration and startup
- **Aegis.Auth.Http**: Package that maps auth endpoints via `app.MapAegisAuthEndpoints()`

The authentication endpoints are minimal APIs in `Aegis.Auth.Http`.
The sample also demonstrates protecting user-defined routes in both styles:

- Controller style: `[AegisAuthorize]` + `HttpContext.GetAegisAuthContext()`
- Minimal API style: `.RequireAegisAuth()`

## Extending User Properties

This sample demonstrates adding app-specific metadata to auth users with a strongly typed derived entity (`AppUser`) mapped as a base-type extension of `User`.

- No change to `Aegis.Auth.Entities.User` required
- Fully typed queries (`context.Users.Select(u => u.IsSpecial)`) in app services
- Useful when you need user flags or profile metadata while keeping auth core reusable
