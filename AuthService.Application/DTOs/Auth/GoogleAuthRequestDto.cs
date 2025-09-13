using AuthService.Application.DTOs.Common;

namespace AuthService.Application.DTOs.Auth
{
    public class GoogleAuthRequestDto
    {
        public string IdToken { get; set; }
        public string AccessToken { get; set; }
        public DeviceInfoDto DeviceInfo { get; set; }
    }
}