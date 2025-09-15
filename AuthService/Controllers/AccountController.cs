using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.DTOs.Account;
using AuthService.Application.Interfaces;
using AuthService.Shared.Exceptions;

namespace AuthService.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;

        public AccountController(IAccountService accountService)
        {
            _accountService = accountService;
        }

        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailDto request)
        {
            try
            {
                var result = await _accountService.VerifyEmailAsync(request);
                return Ok(new { success = result, message = "Email verified successfully" });
            }
            catch (ValidationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
            catch (Exception)
            {
                return StatusCode(500, new { error = "An error occurred during email verification" });
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDto request)
        {
            try
            {
                await _accountService.RequestPasswordResetAsync(request.Email);
                return Ok(new { message = "If the email exists, a password reset link has been sent" });
            }
            catch (Exception)
            {
               
                return Ok(new { message = "If the email exists, a password reset link has been sent" });
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto request)
        {
            try
            {
                var result = await _accountService.ResetPasswordAsync(request);
                return Ok(new { success = result, message = "Password reset successfully" });
            }
            catch (ValidationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
            catch (Exception)
            {
                return StatusCode(500, new { error = "An error occurred during password reset" });
            }
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto request)
        {
            try
            {
                var result = await _accountService.ChangePasswordAsync(request);
                return Ok(new { success = result, message = "Password changed successfully" });
            }
            catch (ValidationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
            catch (Exception)
            {
                return StatusCode(500, new { error = "An error occurred while changing password" });
            }
        }
    }
}