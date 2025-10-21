using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;
using AuthService.Api.Extensions;
using AuthService.Api.Middleware;
using AuthService.Application.Options;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Services;
using AuthService.Infrastructure.Repositories;
using AuthService.Application.Interfaces;
using AuthService.Application.Services;
using System.Text;
using Serilog;
using Serilog.Events;
using AuthService.Infrastructure.Data.Interfaces;
using Serilog.Sinks.SystemConsole.Themes;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Grpc.AspNetCore.Web;
using AuthService.Grpc.Services;

var builder = WebApplication.CreateBuilder(args);

// Kestrel: allow HTTP/1.1 + HTTP/2 for gRPC-Web
builder.WebHost.ConfigureKestrel(options =>
{
    var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
    options.ListenAnyIP(int.Parse(port), listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
    });
});

// ✅ Configure Serilog Logging
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console(theme: AnsiConsoleTheme.Code)
    .WriteTo.File("logs/api-.log",
        rollingInterval: RollingInterval.Day,
        fileSizeLimitBytes: 10 * 1024 * 1024,
        retainedFileCountLimit: 30,
        rollOnFileSizeLimit: true,
        shared: true,
        flushToDiskInterval: TimeSpan.FromSeconds(1))
    .CreateLogger();

builder.Host.UseSerilog();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// gRPC server
builder.Services.AddGrpc();

builder.Services.AddHttpContextAccessor();

// ✅ Register Database (EF Core + Dapper + Neon Connection)
builder.Services.AddDatabase(builder.Configuration);

// ✅ Configure JWT Options
var jwtOptions = builder.Configuration.GetSection("JwtOptions").Get<JwtOptions>();
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("JwtOptions"));

// ✅ Configure Cookie Options
builder.Services.Configure<AuthService.Application.Options.CookieOptions>(
    builder.Configuration.GetSection("CookieOptions"));

// ✅ JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtOptions.Secret)),
            ClockSkew = TimeSpan.Zero
        };

        // Configure to read JWT token from cookies as well as Authorization header
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Try to get token from Authorization header first
                var token = context.Request.Headers["Authorization"]
                    .FirstOrDefault()?.Split(" ").Last();

                // If no token in header, try to get from cookies
                if (string.IsNullOrEmpty(token))
                {
                    token = context.Request.Cookies["access_token"];
                }

                if (!string.IsNullOrEmpty(token))
                {
                    context.Token = token;
                }

                return Task.CompletedTask;
            }
        };
    });

// ✅ Rate Limit Configuration
builder.Services.Configure<RateLimitOptions>(
    builder.Configuration.GetSection("RateLimitOptions"));

// ✅ Common Services
builder.Services.AddScoped<IPasswordService, PasswordService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IDigitalFingerprintService, DigitalFingerprintService>();
builder.Services.AddScoped<IAuthService, AuthService.Application.Services.AuthService>();
builder.Services.AddScoped<IAccountService, AccountService>();

// ✅ CORS Policy
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// ✅ Health Checks (checks Neon PostgreSQL)
builder.Services.AddHealthChecks()
    .AddNpgSql(
        builder.Configuration.GetConnectionString("AuthDb"),
        name: "postgres",
        tags: new[] { "db", "postgres" });

var app = builder.Build();

// ✅ Swagger
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth Service API V1");
        c.RoutePrefix = string.Empty;
    });
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");

// ✅ Serilog request logging
app.UseSerilogRequestLogging();

// ✅ Custom Middleware
app.UseMiddleware<ExceptionMiddleware>();
app.UseMiddleware<RateLimitingMiddleware>();
app.UseMiddleware<DigitalFingerprintMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");

// Enable gRPC-Web (must be before mapping gRPC endpoints)
app.UseGrpcWeb(new GrpcWebOptions { DefaultEnabled = true });

// Map gRPC service from AuthService.Grpc project
app.MapGrpcService<AuthGrpcService>().EnableGrpcWeb();
app.MapGet("/", () => "gRPC Server running...");

// ✅ Optional: Test Neon connection on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    if (db.Database.CanConnect())
        Log.Information("✅ Successfully connected to Neon PostgreSQL Database!");
    else
        Log.Error("❌ Failed to connect to Neon Database!");
}

try
{
    Log.Information("🚀 Starting Auth API...");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "❌ API terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
