using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        private readonly ILogger<TestController> _logger;

        public TestController(ILogger<TestController> logger)
        {
            _logger = logger;
        }

        [HttpGet("authorized")]
        [Authorize]
        public async Task<IActionResult> GetAuthorized()
        {
            return Ok("You are authorized");
        }

        [HttpGet("unauthorized")]
        public async Task<IActionResult> GetUnauthorized()
        {
            return Unauthorized("You're not authorized");
        }

        [HttpGet("user")]
        [Authorize(Roles = "1")]
        public async Task<IActionResult> GetUser()
        {
            _logger.LogInformation("GetUser called");
            return Ok("You are a normal user");
        }

        [HttpGet("admin")]
        [Authorize(Roles = "2")]
        public async Task<IActionResult> GetAdmin()
        {
            _logger.LogInformation("GetAdmin called");
            return Ok("You are an admin");
        }
    }
}
