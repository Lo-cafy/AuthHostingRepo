using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Threading.Tasks;

namespace AuthService.Api.Controllers
{
	[ApiController]
	[Route("api/grpc-test")]
	public class GrpcTestController : ControllerBase
	{
		private readonly IHttpClientFactory _httpClientFactory;
		private readonly ILogger<GrpcTestController> _logger;

		public GrpcTestController(IHttpClientFactory httpClientFactory, ILogger<GrpcTestController> logger)
		{
			_httpClientFactory = httpClientFactory;
			_logger = logger;
		}

		[HttpGet("ping")]
		public async Task<IActionResult> Ping()
		{
			var port = System.Environment.GetEnvironmentVariable("PORT") ?? "8080";
			var baseUrl = $"http://127.0.0.1:{port}/";

			try
			{
				var client = _httpClientFactory.CreateClient();
				var response = await client.GetAsync(baseUrl);
				var body = await response.Content.ReadAsStringAsync();
				return Ok(new { url = baseUrl, status = (int)response.StatusCode, body });
			}
			catch (System.Exception ex)
			{
				_logger.LogError(ex, "Error calling gRPC root endpoint at {BaseUrl}", baseUrl);
				return StatusCode(500, new { url = baseUrl, error = ex.Message });
			}
		}
	}
}


