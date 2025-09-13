using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.Interfaces;

namespace AuthService.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class OAuthController : ControllerBase
    {
        private readonly IOAuthService _oauthService;

        public OAuthController(IOAuthService oauthService)
        {
            _oauthService = oauthService;
        }

        [HttpGet("{provider}/authorize")]
        public async Task<IActionResult> Authorize(string provider)
        {
            try
            {
                var authUrl = await _oauthService.GetAuthorizationUrlAsync(provider);
                return Redirect(authUrl);
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpGet("{provider}/callback")]
        public async Task<IActionResult> Callback(string provider, [FromQuery] string code, [FromQuery] string state)
        {
            try
            {
                var result = await _oauthService.HandleCallbackAsync(provider, code, state);

                // In production, redirect to frontend with tokens
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }
    }
}