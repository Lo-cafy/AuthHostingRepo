using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.DTOs.Auth;
using AuthService.Application.Interfaces;
using AuthService.Shared.Exceptions;

namespace AuthService.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
            try
            {
                var result = await _authService.LoginAsync(request);
                return Ok(result);
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

        //[HttpPost("register")]
        //public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
        //{
        //    var result = await _authService.RegisterAsync(request);

        //    if (!result.Success)
        //        return BadRequest(result);  // Returns 400 with the error message

        //    return Created($"/api/users/{result.UserId}", result);  // Returns 201 Created on success
        //}

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            try
            {
                var result = await _authService.RefreshTokenAsync(request);
                return Ok(result);
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
                return Ok(new { message = "Logged out successfully" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "An error occurred during logout" });
            }
        }

        [HttpGet("user/{id}")]
        [Authorize]
        public async Task<IActionResult> GetUser(Guid id)
        {
            // Placeholder for getting user details
            return Ok(new { userId = id });
        }
    }
}