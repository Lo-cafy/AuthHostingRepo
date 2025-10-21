namespace AuthService.Application.Options
{
    public class CookieOptions
    {
        public bool HttpOnly { get; set; } = true;
        public bool Secure { get; set; } = true;
        public string SameSite { get; set; } = "Strict"; // Strict, Lax, None
        public int AccessTokenExpirationMinutes { get; set; } = 60; // 1 hour
        public int RefreshTokenExpirationDays { get; set; } = 30; // 30 days
        public string AccessTokenName { get; set; } = "access_token";
        public string RefreshTokenName { get; set; } = "refresh_token";
        public string Domain { get; set; } = "";
        public string Path { get; set; } = "/";
    }
}
