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
using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using NLog;
using VaultSharp.V1.SecretsEngines.Database;

namespace Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly ILogger<AuthenticationController> _logger;
        private readonly IConfiguration _config;
        private readonly VaultService _vaultService;
        private readonly IUserInterface _userService;
        private static readonly Logger _nLogger = LogManager.GetCurrentClassLogger();
        private string secret;
        private string issuer;

        public AuthenticationController(ILogger<AuthenticationController> logger, IConfiguration config, VaultService vault, IUserInterface userService)
        {
            _config = config;
            _logger = logger;
            _vaultService = vault;
            _userService = userService;

            // Hent hemmeligheden og udstederen fra Vault
            secret = config["SecretKey"] ?? "noSecret";
            _logger.LogInformation("Secret: {0}", secret);
            issuer = config["IssuerKey"] ?? "noIssuer";
            _logger.LogInformation("Issuer: {0}", issuer);
        }

        private string GenerateJwtToken(string username, string issuer, string secret, int role)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username), "Username cannot be null or empty.");
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Role, role.ToString())
            };

            var token = new JwtSecurityToken(
                issuer,
                "http://localhost/",
                claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                _logger.LogInformation("Generated Token: {0}", tokenString);

            return tokenString;  // lav dette tilbage hvis det ikke virker
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            if (login.username == null || login.password == null)
            {
                var err = "Fejl ved login: Brugernavn eller adgangskode er null.";
                _logger.LogError(err);
                return StatusCode(StatusCodes.Status400BadRequest, err);
            }

            if (secret == null || issuer == null)
            {
                var err = "Fejl ved login: Der opstod en fejl ved login.";
                _logger.LogError(err);
                return StatusCode(StatusCodes.Status500InternalServerError, err);
            }

            _logger.LogInformation("Login forsøgt med brugernavn: {0}", login.username);

            try
            {
                var user = await _userService.ValidateUser(login.username, login.password);
                if (user != null)
                {
                    var token = GenerateJwtToken(login.username, issuer, secret, user.role);
                    LogIPAddress();
                    return Ok(new { token });
                }
                else
                {
                    return Unauthorized("Invalid username or password.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Fejl ved generering af JWT-token: {0}", ex.Message);
                _nLogger.Error(ex, "Fejl ved generering af JWT-token");
                return StatusCode(StatusCodes.Status500InternalServerError, "Der opstod en fejl under login.");
            }
        }

        private void LogIPAddress()
        {
            var hostName = System.Net.Dns.GetHostName();
            var ips = System.Net.Dns.GetHostAddresses(hostName);
            var ipAddr = ips.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString();

            if (!string.IsNullOrEmpty(ipAddr))
            {
                _logger.LogInformation($"XYZ Service responding from {ipAddr}");
                _nLogger.Info($"XYZ Service responding from {ipAddr}");
            }
            else
            {
                _logger.LogWarning("Unable to retrieve the IP address.");
                _nLogger.Warn("Unable to retrieve the IP address.");
            }
        }

        [HttpGet("get-secret")]
        public async Task<IActionResult> GetSecret()
        {
            try
            {
                var secret = await _vaultService.GetSecretAsync("secret", "mySecret");
                return Ok(new { mySecret = secret });
            }
            catch (Exception ex)
            {
                _logger.LogError("Fejl ved hentning af hemmelighedxd: {0}", ex.Message);
                _nLogger.Error(ex, "Fejl ved hentning af hemmelighed");
                return StatusCode(StatusCodes.Status500InternalServerError, "Der opstod en fejl under hentning af hemmelighed.");
            }
        }
    }
}
