using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")] 
    public class TestController : Controller
    {
        private readonly ILogger<TestController> _logger;

        public TestController(ILogger<TestController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        [HttpGet("authorized")]
        public async Task<IActionResult> Get()
        {
            return Ok("You are authorized");
        }

        [HttpGet("unauthorized")]
        public async Task<IActionResult> GetUnauthorized()
        {
            return Unauthorized("You're not authorized");
        }

        [Authorize(Roles = "1")]
        [HttpGet("user")]
        public async Task<IActionResult> GetUser()
        {
            return Ok("You are a normal user");
        }

        [Authorize(Roles = "2")]
        [HttpGet("admin")]
        public async Task<IActionResult> GetAdmin()
        {
            return Ok("You are an admin");
        }
    }
}
