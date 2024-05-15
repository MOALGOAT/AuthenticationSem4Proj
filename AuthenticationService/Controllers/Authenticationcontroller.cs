using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Authentication.Models;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;


namespace Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class Authenticationcontroller : ControllerBase
    {
        private readonly ILogger<Authenticationcontroller> _logger;
        private readonly IConfiguration _config;
        private readonly VaultService _vaultService;

        public Authenticationcontroller(ILogger<Authenticationcontroller> logger, IConfiguration config, VaultService vault)
        {
            _config = config;
            _logger = logger;
            _vaultService = vault;
        }

        private string GenerateJwtToken(string username, string issuer, string secret)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username), "Username cannot be null or empty.");
            }

            var securityKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

            var credentials =
                new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username)
            };

            var token = new JwtSecurityToken(
                issuer,
                "http://localhost/",
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            if (login != null && !string.IsNullOrEmpty(login.username) && !string.IsNullOrEmpty(login.password))
            {
                if (login.username == "admin" && login.password == "1234")
                {
                    try
                    {
                        // Hent hemmeligheden og udstederen fra Vault
                        var secret = await _vaultService.GetSecretAsync("secrets", "SecretKey");
                        var issuer = await _vaultService.GetSecretAsync("secrets", "IssuerKey");

                        // Generer JWT-token med hemmeligheden og udstederen fra Vault
                        var token = GenerateJwtToken(login.username, issuer, secret);

                        // Returner JWT-tokenet som svar
                        return Ok(new { token });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError("Fejl ved generering af JWT-token: {0}", ex.Message);
                        return StatusCode(StatusCodes.Status500InternalServerError, "Der opstod en fejl under login.");
                    }
                }
            }

            return Unauthorized();
        }



        [HttpGet("get-secret")]
        public async Task<IActionResult> GetSecret()
        {
            var secret = await _vaultService.GetSecretAsync("secret", "mySecret");
            return Ok(new { mySecret = secret });
        }




    }
}
