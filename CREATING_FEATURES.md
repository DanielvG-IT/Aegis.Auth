# Creating a Feature Package for Aegis.Auth

This guide walks through creating a new feature package from scratch using the TOTP (Time-based One-Time Password) feature as an example.

## Step 1: Create Package Structure

```
Aegis.Auth.Totp/
├── Aegis.Auth.Totp.csproj
├── Entities/
│   └── TotpDevice.cs
├── Options/
│   └── TotpOptions.cs
├── Abstractions/
│   └── ITotpService.cs
├── Services/
│   └── TotpService.cs
├── Controllers/
│   └── TotpController.cs
├── Extensions/
│   └── TotpExtensions.cs
└── README.md
```

## Step 2: Define Entities

Create entities that consumers must add to their `DbContext`.

**Entities/TotpDevice.cs:**

```csharp
namespace Aegis.Auth.Totp.Entities
{
    /// <summary>
    /// Represents a TOTP device/authenticator for two-factor authentication.
    /// Must be added to consumer's DbContext: DbSet&lt;TotpDevice&gt;
    /// </summary>
    public class TotpDevice
    {
        public string Id { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty; // e.g., "Google Authenticator"
        public string Secret { get; set; } = string.Empty; // Encrypted TOTP secret
        public bool IsVerified { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? VerifiedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
    }
}
```

## Step 3: Define Options

Create strongly-typed configuration options.

**Options/TotpOptions.cs:**

```csharp
namespace Aegis.Auth.Totp.Options
{
    /// <summary>
    /// Configuration options for TOTP authentication.
    /// </summary>
    public sealed class TotpOptions
    {
        /// <summary>
        /// Issuer name shown in authenticator apps.
        /// </summary>
        public string Issuer { get; set; } = string.Empty;

        /// <summary>
        /// Number of digits in TOTP code (6 or 8).
        /// </summary>
        public int Digits { get; set; } = 6;

        /// <summary>
        /// Time step in seconds (typically 30).
        /// </summary>
        public int Period { get; set; } = 30;

        /// <summary>
        /// Algorithm used for TOTP generation.
        /// </summary>
        public string Algorithm { get; set; } = "SHA1";

        /// <summary>
        /// Number of grace periods to allow for clock drift (typically 1).
        /// </summary>
        public int DiscrepancyTolerance { get; set; } = 1;
    }
}
```

## Step 4: Define Service Interface

**Abstractions/ITotpService.cs:**

```csharp
using Aegis.Auth.Result;
using Aegis.Auth.Totp.Entities;

namespace Aegis.Auth.Totp.Abstractions
{
    /// <summary>
    /// Service for TOTP two-factor authentication operations.
    /// </summary>
    public interface ITotpService
    {
        /// <summary>
        /// Generates a new TOTP secret and returns setup information (QR code, manual entry code).
        /// </summary>
        Task<Result<TotpSetupInfo>> GenerateSecretAsync(string userId, string deviceName);

        /// <summary>
        /// Verifies a TOTP code and enables the device.
        /// </summary>
        Task<Result<TotpDevice>> VerifyAndEnableAsync(string deviceId, string code);

        /// <summary>
        /// Validates a TOTP code during sign-in.
        /// </summary>
        Task<Result<bool>> ValidateCodeAsync(string userId, string code);

        /// <summary>
        /// Removes a TOTP device.
        /// </summary>
        Task<Result> DisableAsync(string deviceId, string userId);
    }

    public record TotpSetupInfo(
        string DeviceId,
        string Secret,
        string QrCodeUri,
        string ManualEntryKey
    );
}
```

## Step 5: Implement Service

**Services/TotpService.cs:**

```csharp
using Aegis.Auth.Abstractions;
using Aegis.Auth.Result;
using Aegis.Auth.Totp.Abstractions;
using Aegis.Auth.Totp.Entities;
using Aegis.Auth.Totp.Options;
using Microsoft.EntityFrameworkCore;
using OtpNet; // Example: Use a TOTP library

namespace Aegis.Auth.Totp.Services
{
    public sealed class TotpService : ITotpService
    {
        private readonly IAuthDbContext _dbContext;
        private readonly TotpOptions _options;

        public TotpService(IAuthDbContext dbContext, TotpOptions options)
        {
            _dbContext = dbContext;
            _options = options;
        }

        public async Task<Result<TotpSetupInfo>> GenerateSecretAsync(string userId, string deviceName)
        {
            // Generate secret
            var secretKey = KeyGeneration.GenerateRandomKey(20);
            var base32Secret = Base32Encoding.ToString(secretKey);

            // Create device record
            var device = new TotpDevice
            {
                Id = Guid.NewGuid().ToString(),
                UserId = userId,
                Name = deviceName,
                Secret = base32Secret, // Should be encrypted in production
                IsVerified = false,
                CreatedAt = DateTime.UtcNow
            };

            _dbContext.Set<TotpDevice>().Add(device);
            await _dbContext.SaveChangesAsync();

            // Generate QR code URI
            var user = await _dbContext.Users.FindAsync(userId);
            var qrUri = $"otpauth://totp/{_options.Issuer}:{user?.Email}?secret={base32Secret}&issuer={_options.Issuer}";

            return Result<TotpSetupInfo>.Success(new TotpSetupInfo(
                device.Id,
                base32Secret,
                qrUri,
                base32Secret
            ));
        }

        public async Task<Result<TotpDevice>> VerifyAndEnableAsync(string deviceId, string code)
        {
            var device = await _dbContext.Set<TotpDevice>().FindAsync(deviceId);
            if (device == null)
                return Result<TotpDevice>.Failure(new Error("DEVICE_NOT_FOUND", "TOTP device not found"));

            // Validate code
            var totp = new Totp(Base32Encoding.ToBytes(device.Secret));
            if (!totp.VerifyTotp(code, out _, new VerificationWindow(_options.DiscrepancyTolerance, _options.DiscrepancyTolerance)))
                return Result<TotpDevice>.Failure(new Error("INVALID_CODE", "Invalid TOTP code"));

            // Enable device
            device.IsVerified = true;
            device.VerifiedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            return Result<TotpDevice>.Success(device);
        }

        public async Task<Result<bool>> ValidateCodeAsync(string userId, string code)
        {
            var devices = await _dbContext.Set<TotpDevice>()
                .Where(d => d.UserId == userId && d.IsVerified)
                .ToListAsync();

            if (!devices.Any())
                return Result<bool>.Failure(new Error("NO_DEVICE", "No TOTP device enabled"));

            // Try each device
            foreach (var device in devices)
            {
                var totp = new Totp(Base32Encoding.ToBytes(device.Secret));
                if (totp.VerifyTotp(code, out _, new VerificationWindow(_options.DiscrepancyTolerance, _options.DiscrepancyTolerance)))
                {
                    device.LastUsedAt = DateTime.UtcNow;
                    await _dbContext.SaveChangesAsync();
                    return Result<bool>.Success(true);
                }
            }

            return Result<bool>.Failure(new Error("INVALID_CODE", "Invalid TOTP code"));
        }

        public async Task<Result> DisableAsync(string deviceId, string userId)
        {
            var device = await _dbContext.Set<TotpDevice>()
                .FirstOrDefaultAsync(d => d.Id == deviceId && d.UserId == userId);

            if (device == null)
                return Result.Failure(new Error("DEVICE_NOT_FOUND", "TOTP device not found"));

            _dbContext.Set<TotpDevice>().Remove(device);
            await _dbContext.SaveChangesAsync();

            return Result.Success();
        }
    }
}
```

## Step 6: Create Controller

**Controllers/TotpController.cs:**

```csharp
using Aegis.Auth.Abstractions;
using Aegis.Auth.Totp.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Totp.Controllers
{
    [ApiController]
    [Route("auth/totp")]
    public sealed class TotpController : AegisControllerBase
    {
        private readonly ITotpService _totpService;

        public TotpController(ITotpService totpService, IAegisLogger logger)
            : base(logger)
        {
            _totpService = totpService;
        }

        /// <summary>
        /// POST /auth/totp/setup
        /// Generate TOTP secret and QR code
        /// </summary>
        [HttpPost("setup")]
        public async Task<IActionResult> Setup([FromBody] SetupRequest request)
        {
            // TODO: Validate user is authenticated
            var result = await _totpService.GenerateSecretAsync(request.UserId, request.DeviceName);
            return result.Match(
                success => Ok(success),
                error => BadRequest(error)
            );
        }

        /// <summary>
        /// POST /auth/totp/verify
        /// Verify TOTP code and enable device
        /// </summary>
        [HttpPost("verify")]
        public async Task<IActionResult> Verify([FromBody] VerifyRequest request)
        {
            var result = await _totpService.VerifyAndEnableAsync(request.DeviceId, request.Code);
            return result.Match(
                success => Ok(new { message = "TOTP enabled successfully" }),
                error => BadRequest(error)
            );
        }

        /// <summary>
        /// POST /auth/totp/validate
        /// Validate TOTP code (during 2FA sign-in)
        /// </summary>
        [HttpPost("validate")]
        public async Task<IActionResult> Validate([FromBody] ValidateRequest request)
        {
            var result = await _totpService.ValidateCodeAsync(request.UserId, request.Code);
            return result.Match(
                success => Ok(new { valid = true }),
                error => BadRequest(error)
            );
        }

        /// <summary>
        /// POST /auth/totp/disable
        /// Remove TOTP device
        /// </summary>
        [HttpPost("disable")]
        public async Task<IActionResult> Disable([FromBody] DisableRequest request)
        {
            var result = await _totpService.DisableAsync(request.DeviceId, request.UserId);
            return result.Match(
                success => Ok(new { message = "TOTP disabled successfully" }),
                error => BadRequest(error)
            );
        }
    }

    public record SetupRequest(string UserId, string DeviceName);
    public record VerifyRequest(string DeviceId, string Code);
    public record ValidateRequest(string UserId, string Code);
    public record DisableRequest(string DeviceId, string UserId);
}
```

## Step 7: Create Extension Method

**Extensions/TotpExtensions.cs:**

```csharp
using Aegis.Auth.Abstractions;
using Aegis.Auth.Totp.Abstractions;
using Aegis.Auth.Totp.Options;
using Aegis.Auth.Totp.Services;

namespace Aegis.Auth.Totp.Extensions
{
    public static class TotpExtensions
    {
        /// <summary>
        /// Adds TOTP two-factor authentication support.
        ///
        /// Usage:
        /// <code>
        /// builder.Services.AddAegisAuth&lt;AppDbContext&gt;(...)
        ///     .AddTotp(totp =>
        ///     {
        ///         totp.Issuer = "My App";
        ///         totp.Digits = 6;
        ///     });
        /// </code>
        ///
        /// Requires adding TotpDevice entity to DbContext:
        /// <code>
        /// public DbSet&lt;TotpDevice&gt; TotpDevices => Set&lt;TotpDevice&gt;();
        /// </code>
        /// </summary>
        public static IAegisAuthBuilder AddTotp(
            this IAegisAuthBuilder builder,
            Action<TotpOptions>? configure = null)
        {
            var options = new TotpOptions
            {
                Issuer = builder.Options.AppName // Default from core
            };

            configure?.Invoke(options);

            // Validate
            if (string.IsNullOrWhiteSpace(options.Issuer))
                throw new ArgumentException("TotpOptions.Issuer is required");

            // Register services
            builder.Services.AddSingleton(options);
            builder.Services.AddScoped<ITotpService, TotpService>();

            return builder;
        }
    }
}
```

## Step 8: Document Consumer Usage

**README.md:**

````markdown
# Aegis.Auth.Totp

TOTP (Time-based One-Time Password) two-factor authentication for Aegis.Auth.

## Installation

```bash
dotnet add package Aegis.Auth.Totp
```
````

## Setup

### 1. Update DbContext

Add `TotpDevice` entity to your DbContext:

```csharp
public class AppDbContext : DbContext, IAuthDbContext
{
    // Core entities
    public DbSet<User> Users => Set<User>();
    public DbSet<Session> Sessions => Set<Session>();

    // TOTP feature entity
    public DbSet<TotpDevice> TotpDevices => Set<TotpDevice>();
}
```

### 2. Configure in Program.cs

```csharp
builder.Services
    .AddAegisAuth<AppDbContext>(options => { ... })
    .AddTotp(totp =>
    {
        totp.Issuer = "My Application";
        totp.Digits = 6;  // 6 or 8
        totp.Period = 30; // seconds
    });
```

### 3. Run Migration

```bash
dotnet ef migrations add AddTotpDevice
dotnet ef database update
```

## Endpoints

- `POST /auth/totp/setup` - Generate TOTP secret and QR code
- `POST /auth/totp/verify` - Verify code and enable device
- `POST /auth/totp/validate` - Validate code during sign-in
- `POST /auth/totp/disable` - Remove TOTP device

## Usage Flow

### Setup TOTP

1. Generate secret:

```javascript
const response = await fetch("/auth/totp/setup", {
    method: "POST",
    body: JSON.stringify({
        userId: "user-id",
        deviceName: "Google Authenticator",
    }),
});

const { deviceId, qrCodeUri, manualEntryKey } = await response.json();
```

2. Show QR code to user (render `qrCodeUri`)

3. Verify code:

```javascript
await fetch("/auth/totp/verify", {
    method: "POST",
    body: JSON.stringify({ deviceId, code: "123456" }),
});
```

### Sign In with TOTP

After email/password sign-in, validate TOTP:

```javascript
const response = await fetch("/auth/totp/validate", {
    method: "POST",
    body: JSON.stringify({ userId: "user-id", code: "123456" }),
});
```

## Configuration Options

| Option                 | Default    | Description                      |
| ---------------------- | ---------- | -------------------------------- |
| `Issuer`               | (required) | Name shown in authenticator apps |
| `Digits`               | 6          | Code length (6 or 8)             |
| `Period`               | 30         | Time step in seconds             |
| `Algorithm`            | SHA1       | Hash algorithm                   |
| `DiscrepancyTolerance` | 1          | Grace periods for clock drift    |

````

## Step 9: Create .csproj

**Aegis.Auth.Totp.csproj:**
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <!-- Reference core package -->
    <ProjectReference Include="../Aegis.Auth/Aegis.Auth.csproj" />

    <!-- TOTP library -->
    <PackageReference Include="Otp.NET" Version="1.4.0" />
  </ItemGroup>
</Project>
````

## Checklist

- [x] Define entities (`TotpDevice`)
- [x] Define options (`TotpOptions`)
- [x] Define service interface (`ITotpService`)
- [x] Implement service (`TotpService`)
- [x] Create controller (`TotpController`)
- [x] Create extension method (`.AddTotp()`)
- [x] Document consumer requirements
- [x] Create README with examples
- [x] Add .csproj with dependencies

## Testing the Feature

```csharp
// In consumer's test project
public class TotpIntegrationTests
{
    [Fact]
    public async Task CanSetupAndValidateTotp()
    {
        var services = new ServiceCollection()
            .AddAegisAuth<TestDbContext>(...)
            .AddTotp(totp => totp.Issuer = "Test")
            .Services
            .BuildServiceProvider();

        var totpService = services.GetRequiredService<ITotpService>();

        var setup = await totpService.GenerateSecretAsync("user-id", "Test Device");
        Assert.True(setup.IsSuccess);

        // Generate code from secret
        var totp = new Totp(Base32Encoding.ToBytes(setup.Value.Secret));
        var code = totp.ComputeTotp();

        var verify = await totpService.VerifyAndEnableAsync(setup.Value.DeviceId, code);
        Assert.True(verify.IsSuccess);
    }
}
```

## Ship It! 🚀

Package is now ready to publish to NuGet:

```bash
dotnet pack -c Release
dotnet nuget push bin/Release/Aegis.Auth.Totp.1.0.0.nupkg
```

Consumers can now:

```bash
dotnet add package Aegis.Auth.Totp
```

And use:

```csharp
.AddAegisAuth<AppDbContext>(...)
    .AddTotp(totp => totp.Issuer = "My App")
```

**Zero core changes required.** ✨
