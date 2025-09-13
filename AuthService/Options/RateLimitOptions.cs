namespace AuthService.Application.Options
{
    public class RateLimitOptions
    {
        public int RequestLimit { get; set; }
        public int WindowSizeInMinutes { get; set; }
    }
}