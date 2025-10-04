using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
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
using Serilog.Sinks.SystemConsole.Themes;

var builder = WebApplication.CreateBuilder(args);

 
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
builder.Services.AddHttpContextAccessor();

 
builder.Services.AddDatabase(builder.Configuration);


builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("JwtOptions"));
var jwtOptions = builder.Configuration.GetSection("JwtOptions").Get<JwtOptions>();

if (jwtOptions == null || string.IsNullOrWhiteSpace(jwtOptions.Secret))
    throw new InvalidOperationException("JWT Secret is missing from appsettings.json!");

Console.WriteLine($"JWT Secret Loaded: (len={jwtOptions.Secret.Length})");


builder.Services.AddScoped<IJwtService, JwtService>();

 
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Secret)),
            ClockSkew = TimeSpan.Zero
        };
    });

 
builder.Services.Configure<RateLimitOptions>(builder.Configuration.GetSection("RateLimitOptions"));

 
builder.Services.AddScoped<IPasswordService, PasswordService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IDigitalFingerprintService, DigitalFingerprintService>();
builder.Services.AddScoped<IAuthService, AuthService.Application.Services.AuthService>();
builder.Services.AddScoped<IAccountService, AccountService>();

 
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

 
builder.Services.AddHealthChecks()
    .AddNpgSql(
        builder.Configuration.GetConnectionString("AuthDb"),
        name: "postgres",
        tags: new[] { "db", "postgres" });

var app = builder.Build();

 
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth Service API v1");
        c.RoutePrefix = string.Empty;
    });
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");

 
app.UseSerilogRequestLogging();

 
app.UseMiddleware<ExceptionMiddleware>();
app.UseMiddleware<RateLimitingMiddleware>();
app.UseMiddleware<DigitalFingerprintMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");

 
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    try
    {
        if (db.Database.CanConnect())
            Log.Information("✅ Successfully connected to Neon PostgreSQL Database!");
        else
            Log.Error("❌ Failed to connect to Neon Database!");
    }
    catch (Exception ex)
    {
        Log.Error(ex, "❌ Error checking Neon Database connection!");
    }
}

try
{
    Log.Information("🚀 Starting Auth API...");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "❌ API terminated unexpectedly!");
}
finally
{
    Log.CloseAndFlush();
}
