using AuthService.Grpc.Interceptors;
using AuthService.Grpc.Services;
using AuthService.Application.Interfaces;
using AuthService.Application.Services;
using AuthService.Infrastructure.Interfaces;
using AuthService.Infrastructure.Repositories;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;
using Grpc.HealthCheck;
using Serilog.Events;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateLogger();

try
{
    // Add Serilog to the logging pipeline
    builder.Host.UseSerilog((hostingContext, loggerConfiguration) =>
        loggerConfiguration
            .ReadFrom.Configuration(hostingContext.Configuration)
            .Enrich.FromLogContext()
            .WriteTo.Console());

    // Add gRPC services
    builder.Services.AddGrpc(options =>
    {
        options.Interceptors.Add<ExceptionInterceptor>();
        options.Interceptors.Add<AuthInterceptor>();
        options.Interceptors.Add<RateLimitInterceptor>();
    });

    // Register Application Services
    builder.Services.AddScoped<IOAuthService, AuthService.Application.Services.OAuthService>();
    builder.Services.AddScoped<IDeviceFingerprintService, DeviceFingerprintService>();
    builder.Services.AddScoped<IJwtService, JwtService>();
    builder.Services.AddScoped<ISecurityService, SecurityService>();

    // Register Repositories
    builder.Services.AddScoped<IOAuthRepository, OAuthRepository>();
    builder.Services.AddScoped<IDeviceFingerprintRepository, DeviceFingerprintRepository>();
    builder.Services.AddScoped<IUserRepository, UserRepository>();

    // Add health checks
    builder.Services.AddGrpc();
    builder.Services.AddHealthChecks()
        .AddNpgSql(
            builder.Configuration.GetConnectionString("DefaultConnection"),
            name: "postgres",
            tags: new[] { "db", "postgres" });

    // Add gRPC Health Checks
    builder.Services.AddGrpcHealthChecks()
        .AddCheck("Sample", () => HealthCheckResult.Healthy());

    var app = builder.Build();

    // Configure the HTTP request pipeline
    if (app.Environment.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }

    // Use Serilog request logging
    app.UseSerilogRequestLogging();

    // Map gRPC services
    app.MapGrpcService<OAuthGrpcService>();
    app.MapGrpcService<DeviceFingerprintGrpcService>();

    // Map health check endpoint
    app.MapHealthChecks("/health");

    // Map gRPC health service
    app.MapGrpcHealthChecksService();

    app.MapGet("/", () => "AuthService gRPC is running");

    Log.Information("Starting AuthService gRPC");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "AuthService gRPC terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}