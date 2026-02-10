# Aegis.Auth Sample API

This is a sample ASP.NET Core Web API project that demonstrates how to use the Aegis.Auth library for authentication.

## Features

- ✅ Email/Password authentication
- ✅ Secure session management with signed cookies
- ✅ Cookie-based session caching
- ✅ In-memory database for testing
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

## Configuration

The Aegis.Auth configuration is in `Program.cs`:

- **Secret**: Used for signing cookies and tokens
- **Email/Password**: Enabled with verification optional for testing
- **Session**: 1-hour expiration with 5-minute cookie cache
- **Cookie Cache**: Enabled to reduce database lookups

## Architecture

- **Data/SampleAuthDbContext.cs**: EF Core DbContext implementing `IAuthDbContext`
- **Data/DataSeeder.cs**: Seeds test data into the in-memory database
- **Controllers/HealthController.cs**: Health check and diagnostics endpoint
- **Program.cs**: Application configuration and startup

The actual authentication controllers come from the Aegis.Auth library (`SignInController`, etc.).
