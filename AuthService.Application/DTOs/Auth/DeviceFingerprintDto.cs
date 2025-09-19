namespace AuthService.Application.DTOs.Auth
{
    public class DeviceFingerprintDto
    {
        public string OperatingSystem { get; set; }
        public string Browser { get; set; }
        public string UserAgent { get; set; }
        public string IpAddress { get; set; }
        public string ScreenResolution { get; set; }
        public string TimeZone { get; set; }
        public object? Location { get; set; }
        public string Language { get; set; }
        public bool HasTouchScreen { get; set; }
    }
}