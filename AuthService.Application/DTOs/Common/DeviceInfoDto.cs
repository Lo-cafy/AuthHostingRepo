namespace AuthService.Application.DTOs.Common
{
    public class DeviceInfoDto
    {
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public LocationDto Location { get; set; }
    }

    public class LocationDto
    {
        public string Country { get; set; }
        public string City { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
    }
}