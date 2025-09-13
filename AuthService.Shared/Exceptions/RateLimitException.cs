using System;

namespace AuthService.Shared.Exceptions
{
    public class RateLimitException : Exception
    {
        public RateLimitException(string message) : base(message) { }
    }
}