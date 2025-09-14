using AuthService.Grpc.Interceptors;
using AuthService.Grpc.Services;
using AuthService.Infrastructure.Data;
using AuthService.Infrastructure.Data.Interfaces;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;
using Serilog.Events;
using Grpc.HealthCheck;
using Serilog.Sinks.SystemConsole.Themes;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console(theme: AnsiConsoleTheme.Code)
    .WriteTo.File("logs/grpc-.log",
        rollingInterval: RollingInterval.Day,
        fileSizeLimitBytes: 10 * 1024 * 1024,
        retainedFileCountLimit: 30,
        rollOnFileSizeLimit: true,
        shared: true,
        flushToDiskInterval: TimeSpan.FromSeconds(1))
    .CreateLogger();

try
{
    // Configure Kestrel
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ListenLocalhost(5001, o => o.Protocols = HttpProtocols.Http2);
    });

    // Add Serilog to the logging pipeline
    builder.Host.UseSerilog();

    // Add gRPC services
    builder.Services.AddGrpc(options =>
    {
        options.Interceptors.Add<ExceptionInterceptor>();
        options.Interceptors.Add<AuthInterceptor>();
        options.Interceptors.Add<RateLimitInterceptor>();
        options.EnableDetailedErrors = builder.Environment.IsDevelopment();
    });

    // Configure Database
    builder.Services.Configure<DatabaseOptions>(
        builder.Configuration.GetSection(DatabaseOptions.SectionName));
    builder.Services.AddSingleton<IDbConnectionFactory, NpgsqlConnectionFactory>();

 

    // Add health checks
    builder.Services.AddHealthChecks()
        .AddNpgSql(
            builder.Configuration.GetConnectionString("AuthDb"),
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
    app.MapGrpcService<AuthGrpcService>();
    app.MapGrpcService<OAuthGrpcService>();
    app.MapGrpcService<DeviceFingerprintGrpcService>();

    // Map health check endpoints
    app.MapHealthChecks("/health");
    app.MapGrpcHealthChecksService();

    app.MapGet("/", () => "AuthService gRPC is running. gRPC endpoints are available.");

    Log.Information("Starting AuthService gRPC on port 5001");
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