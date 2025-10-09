using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using AuthService.Application.Exceptions;

namespace AuthService.Api.Middleware
{
    public class ExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionMiddleware> _logger;

        public ExceptionMiddleware(RequestDelegate next, ILogger<ExceptionMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred");
                await HandleExceptionAsync(context, ex);
            }
        }

        private static async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";

            var response = new
            {
                error = new
                {
                    message = "An error occurred while processing your request.",
                    detail = exception.Message
                }
            };

            switch (exception)
            {
                case ValidationException:
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response = new
                    {
                        error = new
                        {
                            message = exception.Message,
                            detail = "Validation failed"
                        }
                    };
                    break;

                case AuthException:
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    response = new
                    {
                        error = new
                        {
                            message = exception.Message,
                            detail = "Authentication failed"
                        }
                    };
                    break;

                case RateLimitException:
                    context.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
                    response = new
                    {
                        error = new
                        {
                            message = exception.Message,
                            detail = "Rate limit exceeded"
                        }
                    };
                    break;

                default:
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    break;
            }

            var jsonResponse = JsonSerializer.Serialize(response);
            await context.Response.WriteAsync(jsonResponse);
        }
    }
}