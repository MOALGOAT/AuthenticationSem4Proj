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
using Authentication.Service;
using Models;

namespace Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly ILogger<AuthenticationController> _logger;
        private readonly IConfiguration _config;
        private readonly VaultService _vaultService;
        private readonly IUserService _userService;
        private static readonly Logger _nLogger = LogManager.GetCurrentClassLogger();
        private string secret;
        private string issuer;

        public AuthenticationController(ILogger<AuthenticationController> logger, IConfiguration config, VaultService vault, IUserService userService)
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

        private string GenerateJwtToken(string username, string issuer, string secret, int role, Guid _id)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username), "Username cannot be null or empty.");
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Role, role.ToString()),
                new Claim("id", _id.ToString())
            };

            var token = new JwtSecurityToken(
                issuer,
                "http://localhost/",
                claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            _logger.LogInformation("Generated Token: {0}", tokenString);

            return tokenString;
        }

        [AllowAnonymous]
        [HttpPost("loginuser")]
        public async Task<IActionResult> LoginUser([FromBody] LoginDTO user)
        {
            _logger.LogInformation("Attempting to log in user {Username}", user.username);

            var validUser = await _userService.ValidateUser(user);
            try
            {
                if (validUser.role == 1)
                {
                    var token = GenerateJwtToken(user.username, issuer, secret, 1, _id: validUser._id);
                    LogIPAddress();
                    _logger.LogInformation("User {Username} logged in successfully", user.username);
                    return Ok(new { token });
                }
                else
                {
                    _logger.LogWarning("Invalid role for user {Username}. Login attempt rejected.", user.username);
                    return Unauthorized("Invalid username or password.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while generating JWT token: {Message}", ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred during login.");
            }
        }

        [AllowAnonymous]
        [HttpPost("loginadmin")]
        public async Task<IActionResult> LoginAdmin([FromBody] LoginDTO user)
        {
            _logger.LogInformation("Attempting to log in admin user {Username}", user.username);

            var validUser = await _userService.ValidateUser(user);

            try
            {
                if (validUser.role == 2)
                {
                    var token = GenerateJwtToken(user.username, issuer, secret, 2, _id: validUser._id);
                    LogIPAddress();
                    _logger.LogInformation("Admin user {Username} logged in successfully", user.username);
                    return Ok(new { token });
                }
                else
                {
                    _logger.LogWarning("Invalid role for admin user {Username}. Login attempt rejected.", user.username);
                    return Unauthorized("Invalid username or password.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while generating JWT token: {Message}", ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred during login.");
            }
        }

        [HttpGet("authorized")]
        [Authorize]
        public IActionResult GetAuthorized()
        {
            _logger.LogInformation("Authorized endpoint called");
            return Ok("You are authorized");
        }

        [HttpGet("unauthorized")]
        public IActionResult GetUnauthorized()
        {
            _logger.LogInformation("Unauthorized endpoint called");
            return Unauthorized("You're not authorized");
        }

        [HttpGet("user")]
        [Authorize(Roles = "1")]
        public IActionResult GetUser()
        {
            _logger.LogInformation("GetUser called");
            return Ok("You are a normal user");
        }

        [HttpGet("admin")]
        [Authorize(Roles = "2")]
        public IActionResult GetAdmin()
        {
            _logger.LogInformation("GetAdmin called");
            return Ok("You are an admin");
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
                _logger.LogInformation("Secret retrieved successfully");
                return Ok(new { mySecret = secret });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while retrieving secret: {Message}", ex.Message);
                _nLogger.Error(ex, "Error occurred while retrieving secret");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while retrieving the secret.");
            }
        }
    }
}
