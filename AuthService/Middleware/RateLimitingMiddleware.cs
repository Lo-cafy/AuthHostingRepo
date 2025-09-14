using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using AuthService.Application.Options;
using Microsoft.AspNetCore.RateLimiting;

namespace AuthService.Api.Middleware
{
    public class RateLimitingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly RateLimitOptions _options;
        private static readonly ConcurrentDictionary<string, RateLimitInfo> _clients = new();

        public RateLimitingMiddleware(RequestDelegate next, IOptions<RateLimitOptions> options)
        {
            _next = next;
            _options = options.Value;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var clientId = GetClientIdentifier(context);
            var now = DateTime.UtcNow;

            var rateLimitInfo = _clients.AddOrUpdate(clientId,
                new RateLimitInfo { Count = 1, WindowStart = now },
                (key, existing) =>
                {
                    if (now.Subtract(existing.WindowStart).TotalMinutes >= _options.WindowSizeInMinutes)
                    {
                        existing.Count = 1;
                        existing.WindowStart = now;
                    }
                    else
                    {
                        existing.Count++;
                    }
                    return existing;
                });

            if (rateLimitInfo.Count > _options.RequestLimit)
            {
                context.Response.StatusCode = 429;
                await context.Response.WriteAsync("Rate limit exceeded. Try again later.");
                return;
            }

            await _next(context);
        }

        private string GetClientIdentifier(HttpContext context)
        {
            // Use IP address as identifier
            return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }

        private class RateLimitInfo
        {
            public int Count { get; set; }
            public DateTime WindowStart { get; set; }
        }
    }
}