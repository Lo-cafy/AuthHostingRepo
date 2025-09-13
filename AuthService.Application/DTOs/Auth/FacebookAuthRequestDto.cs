using AuthService.Application.DTOs.Common;

namespace AuthService.Application.DTOs.Auth
{
    public class FacebookAuthRequestDto
    {
        public string AccessToken { get; set; }
        public DeviceInfoDto DeviceInfo { get; set; }
    }
}