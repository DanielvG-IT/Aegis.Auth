# Aegis.Auth

Modular authentication library for .NET, inspired by BetterAuth (TypeScript).

## Features

- User management (register, login, sessions)
- Password, passkeys, TOTP, OAuth support
- Hooks system (OnUserCreated, OnEmailVerified, etc.)
- Modular architecture (core + HTTP endpoints + optional plugins)
- Designed for extensibility and clean Program.cs integration

## Getting Started

Clone the repo:

```bash
git clone https://github.com/DanielvG-IT/Aegis.Auth.git
cd Aegis.Auth
```

Open in Visual Studio / Rider / VS Code:

```bash
dotnet restore
dotnet build

```

## Project Structure

```
src/
  Aegis.Auth/
  Aegis.Auth.Http/
  Aegis.Auth.Totp/
  Aegis.Auth.Passkeys/

tests/
  Aegis.Auth.Tests/
```

## Contributing

PRs welcome! Please follow the .editorconfig and add tests for new features.
