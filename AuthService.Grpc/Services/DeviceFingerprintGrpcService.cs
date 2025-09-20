using System;
using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using AuthService.Application.Interfaces;
using AuthService.Application.Services;
using AuthService.Application.DTOs.Auth;
using Microsoft.Extensions.Logging;
using Google.Protobuf.WellKnownTypes;
using AuthService.Application.Services;
using AuthService.Grpc.Protos;

namespace AuthService.Grpc.Services
{
    public class DeviceFingerprintGrpcService : Protos.DeviceFingerprintService.DeviceFingerprintServiceBase
    {
        private readonly IDeviceFingerprintService _deviceFingerprintService;
        private readonly ILogger<DeviceFingerprintGrpcService> _logger;

        public DeviceFingerprintGrpcService(
            IDeviceFingerprintService deviceFingerprintService,
            ILogger<DeviceFingerprintGrpcService> logger)
        {
            _deviceFingerprintService = deviceFingerprintService;
            _logger = logger;
        }

        public override async Task<RegisterDeviceResponse> RegisterDevice(RegisterDeviceRequest request, ServerCallContext context)
        {
            try
            {
                var userId = int.Parse(request.UserId);
                var deviceInfo = new DeviceFingerprintDto
                {
                    OperatingSystem = request.DeviceInfo.OperatingSystem,
                    Browser = request.DeviceInfo.Browser,
                    UserAgent = request.DeviceInfo.UserAgent,
                    IpAddress = request.DeviceInfo.IpAddress,
                    ScreenResolution = request.DeviceInfo.ScreenResolution,
                    TimeZone = request.DeviceInfo.TimeZone,
                    Language = request.DeviceInfo.Language,
                    HasTouchScreen = request.DeviceInfo.HasTouchScreen
                };

                var result = await _deviceFingerprintService.RegisterDeviceAsync(userId, deviceInfo);
                var fingerprintHash = await _deviceFingerprintService.GenerateFingerprintAsync(deviceInfo);

                return new RegisterDeviceResponse
                {
                    Success = true, 
                    FingerprintId = new int().ToString(),
                    FingerprintHash = fingerprintHash,
                    Message = "Device registered successfully"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register device");
                return new RegisterDeviceResponse
                {
                    Success = false,
                    Message = ex.Message
                };
            }
        }

        public override async Task<ValidateFingerprintResponse> ValidateFingerprint(ValidateFingerprintRequest request, ServerCallContext context)
        {
            try
            {
                var userId = int.Parse(request.UserId);
                var isValid = await _deviceFingerprintService.ValidateFingerprintAsync(userId, request.FingerprintHash);

                 
                if (isValid)
                {
                    var devices = await _deviceFingerprintService.GetUserDevicesAsync(userId);
                    var device = devices.FirstOrDefault(d =>
                        _deviceFingerprintService.GenerateFingerprintAsync(d).Result == request.FingerprintHash);

                    return new ValidateFingerprintResponse
                    {
                        IsValid = true,
                        IsTrusted = device != null, 
                        LastUsedAt = Timestamp.FromDateTime(DateTime.UtcNow)
                    };
                }

                return new ValidateFingerprintResponse
                {
                    IsValid = false,
                    IsTrusted = false
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate fingerprint");
                throw new RpcException(new Status(StatusCode.Internal, ex.Message));
            }
        }

        public override async Task<TrustDeviceResponse> TrustDevice(TrustDeviceRequest request, ServerCallContext context)
        {
            try
            {
                var userId = int.Parse(request.UserId);
                var fingerprintId = int.Parse(request.FingerprintId);

                var trustInfo = new TrustDeviceDto
                {
                    FingerprintId = fingerprintId,
                    Trust = request.Trust
                };

                var success = await _deviceFingerprintService.TrustDeviceAsync(userId, trustInfo);

                return new TrustDeviceResponse
                {
                    Success = success,
                    Message = success
                        ? (request.Trust ? "Device trusted successfully" : "Device trust removed")
                        : "Failed to update device trust"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to trust device");
                return new TrustDeviceResponse
                {
                    Success = false,
                    Message = ex.Message
                };
            }
        }

        public override async Task<GetUserDevicesResponse> GetUserDevices(GetUserDevicesRequest request, ServerCallContext context)
        {
            try
            {
                var userId = int.Parse(request.UserId);
                var devices = await _deviceFingerprintService.GetUserDevicesAsync(userId);

                var response = new GetUserDevicesResponse();
                foreach (var device in devices)
                {
                    response.Devices.Add(new UserDevice
                    {
                        FingerprintId = new int().ToString(),
                        OperatingSystem = device.OperatingSystem,
                        Browser = device.Browser,
                        IsTrusted = false, 
                        CreatedAt = Timestamp.FromDateTime(DateTime.UtcNow),
                        LastUsedAt = Timestamp.FromDateTime(DateTime.UtcNow)
                    });
                }

                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user devices");
                throw new RpcException(new Status(StatusCode.Internal, ex.Message));
            }
        }

        public override async Task<CheckDeviceTrustResponse> CheckDeviceTrust(CheckDeviceTrustRequest request, ServerCallContext context)
        {
            try
            {
                var userId = int.Parse(request.UserId);
                var isValid = await _deviceFingerprintService.ValidateFingerprintAsync(userId, request.DeviceFingerprint);

                // Determine trust level and MFA requirement
                var trustLevel = "untrusted";
                var requiresMfa = true;

                if (isValid)
                {
                    // Logic to determine trust level
                    trustLevel = "partial";
                    requiresMfa = true; // You might want to check if device is fully trusted
                }

                return new CheckDeviceTrustResponse
                {
                    IsTrusted = isValid,
                    RequiresMfa = requiresMfa,
                    TrustLevel = trustLevel
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check device trust");
                throw new RpcException(new Status(StatusCode.Internal, ex.Message));
            }
        }
    }
}