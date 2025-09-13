using System;

namespace AuthService.Shared.Exceptions
{
    public class AuthException : Exception
    {
        public AuthException(string message) : base(message) { }
    }
}