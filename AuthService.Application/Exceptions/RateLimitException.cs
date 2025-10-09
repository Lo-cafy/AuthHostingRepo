using System;

namespace AuthService.Application.Exceptions
{
    public class RateLimitException : Exception
    {
        public RateLimitException(string message) : base(message) { }
    }
}


