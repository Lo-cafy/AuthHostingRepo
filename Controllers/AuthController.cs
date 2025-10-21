using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.Interfaces;
using AuthService.Application.Options;
using AuthService.Shared.Exceptions;

namespace AuthService.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly AuthService.Application.Options.CookieOptions _cookieOptions;

        public AuthController(IAuthService authService, IOptions<AuthService.Application.Options.CookieOptions> cookieOptions)
        {
            _authService = authService;
            _cookieOptions = cookieOptions.Value;
        }

        private CookieOptions CreateCookieOptions(DateTime? expires = null)
        {
            var sameSiteMode = _cookieOptions.SameSite.ToLower() switch
            {
                "lax" => SameSiteMode.Lax,
                "none" => SameSiteMode.None,
                _ => SameSiteMode.Strict
            };

            return new CookieOptions
            {
                HttpOnly = _cookieOptions.HttpOnly,
                Secure = _cookieOptions.Secure,
                SameSite = sameSiteMode,
                Expires = expires,
                Domain = string.IsNullOrEmpty(_cookieOptions.Domain) ? null : _cookieOptions.Domain,
                Path = _cookieOptions.Path
            };
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
            try
            {
                var result = await _authService.LoginAsync(request);
                
               
                var accessTokenCookieOptions = CreateCookieOptions(result.ExpiresAt);
                var refreshTokenCookieOptions = CreateCookieOptions(DateTime.UtcNow.AddDays(_cookieOptions.RefreshTokenExpirationDays));

                
                Response.Cookies.Append(_cookieOptions.AccessTokenName, result.AccessToken, accessTokenCookieOptions);
                Response.Cookies.Append(_cookieOptions.RefreshTokenName, result.RefreshToken, refreshTokenCookieOptions);

                 
                var responseWithoutTokens = new
                {
                    ExpiresIn = result.ExpiresIn,
                    ExpiresAt = result.ExpiresAt,
                    User = result.User,
                    Role = result.Role,
                    Message = "Login successful - tokens set in cookies"
                };

                return Ok(responseWithoutTokens);
            }
            catch (RateLimitException ex)
            {
                return StatusCode(429, new { error = ex.Message });
            }
            catch (AuthException ex)
            {
                return Unauthorized(new { error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during login" });
            }
        }


        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            try
            {
                
                if (string.IsNullOrEmpty(request?.RefreshToken))
                {
                    var refreshTokenFromCookie = Request.Cookies[_cookieOptions.RefreshTokenName];
                    if (string.IsNullOrEmpty(refreshTokenFromCookie))
                    {
                        return BadRequest(new { error = "Refresh token not found in request body or cookies" });
                    }
                    request = new RefreshTokenRequestDto { RefreshToken = refreshTokenFromCookie };
                }

                var result = await _authService.RefreshTokenAsync(request);

               
                var cookieOptions = CreateCookieOptions(DateTime.UtcNow.AddSeconds(result.ExpiresIn));

                Response.Cookies.Append(_cookieOptions.AccessTokenName, result.AccessToken, cookieOptions);

               
                var responseWithoutToken = new
                {
                    ExpiresIn = result.ExpiresIn,
                    Message = "Token refreshed successfully - new access token set in cookie"
                };

                return Ok(responseWithoutToken);
            }
            catch (AuthException ex)
            {
                return Unauthorized(new { error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred while refreshing token" });
            }
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var jti = User.FindFirst("jti")?.Value;
                if (string.IsNullOrEmpty(jti))
                {
                    return BadRequest(new { error = "Invalid token" });
                }

                await _authService.LogoutAsync(jti);

              
                var cookieOptions = CreateCookieOptions(DateTime.UtcNow.AddDays(-1)); 

                Response.Cookies.Append(_cookieOptions.AccessTokenName, "", cookieOptions);
                Response.Cookies.Append(_cookieOptions.RefreshTokenName, "", cookieOptions);

                return Ok(new { message = "Logged out successfully - cookies cleared" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during logout" });
            }
        }

        [HttpGet("user/{id}")]
        [Authorize]
        public async Task<IActionResult> GetUser(int id)
        {
            return Ok(new { userId = id });
        }
    }
}