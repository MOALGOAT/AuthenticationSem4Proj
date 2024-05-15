using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Authentication.Models;

namespace Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")] 
    public class TestController : Controller
    {
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

    }
}
