using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using AuthService.Application.DTOs.Common;
using Newtonsoft.Json;

namespace AuthService.Api.Middleware
{
    public class DigitalFingerprintMiddleware
    {
        private readonly RequestDelegate _next;

        public DigitalFingerprintMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Extract device info from request
            var deviceInfo = new DeviceInfoDto
            {
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                UserAgent = context.Request.Headers["User-Agent"].ToString(),
            };

            // Store in HttpContext for later use
            context.Items["DeviceInfo"] = deviceInfo;

            await _next(context);
        }
    }
}