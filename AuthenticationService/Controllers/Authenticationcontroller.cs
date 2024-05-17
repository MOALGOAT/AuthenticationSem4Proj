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
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;
using NLog;

namespace Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly ILogger<AuthenticationController> _logger;
        private readonly IConfiguration _config;
        private readonly VaultService _vaultService;
        private static readonly Logger _nLogger = LogManager.GetCurrentClassLogger();
        private string secret;
        private string issuer;

        public AuthenticationController(ILogger<AuthenticationController> logger, IConfiguration config, VaultService vault)
        {
            _config = config;
            _logger = logger;
            _vaultService = vault;

            // Hent hemmeligheden og udstederen fra Vault
            secret = _vaultService.GetSecretAsync("secrets", "SecretKey").ToString();
            issuer = _vaultService.GetSecretAsync("secrets", "IssuerKey").ToString();

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
            //lav test og logging
            if(login.username == null || login.password == null)
            {
                var err = "Fejl ved login: Brugernavn eller adgangskode er null.";
                _logger.LogError(err);
                return StatusCode(StatusCodes.Status400BadRequest, err);
            }

            //lav test og logging
            if(secret == null || issuer == null)
            {
                var err = "Fejl ved login: Der opstod en fejl ved login.";
                _logger.LogError(err);
                return StatusCode(StatusCodes.Status500InternalServerError, err);
            }

            if (login != null && !string.IsNullOrEmpty(login.username) && !string.IsNullOrEmpty(login.password))
            {
                if (login.username == "admin" && login.password == "1234")
                {
                    try
                    {
                        // Generer JWT-token med hemmeligheden og udstederen fra Vault
                        var token = GenerateJwtToken(login.username, issuer, secret);

                        // Log IP-adressen
                        LogIPAddress();

                        // Returner JWT-tokenet som svar
                        return Ok(new { token });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError("Fejl ved generering af JWT-token: {0}", ex.Message);
                        _nLogger.Error(ex, "Fejl ved generering af JWT-token");
                        return StatusCode(StatusCodes.Status500InternalServerError, "Der opstod en fejl under login.");
                    }
                }
            }

            return Unauthorized();
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
                _logger.LogError("Fejl ved hentning af hemmelighed: {0}", ex.Message);
                _nLogger.Error(ex, "Fejl ved hentning af hemmelighed");
                return StatusCode(StatusCodes.Status500InternalServerError, "Der opstod en fejl under hentning af hemmelighed.");
            }
        }
    }
}
