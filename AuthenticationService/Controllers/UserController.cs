/*using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Authentication.Service;

namespace Authentication.Controllers 
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<UserController> _logger;

        public UserController(IUserService userService, ILogger<UserController> logger)
        {
            _userService = userService;
            _logger = logger;
        }

        [HttpGet("getuser/{_id}")]
        public async Task<IActionResult> GetUser(Guid _id)
        {
            try
            {
                _logger.LogInformation("Getting user with id: {0}", _id);
                var response = await _userService.GetUserAsync(_id);
                if (response == null)
                {
                    _logger.LogInformation("User with id: {0} not found", _id);
                    return NotFound();
                }
                
                var content = await response.Content.ReadAsStringAsync();
                _logger.LogInformation("User with id: {0} found", _id);
                return Ok(content);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, "An error occurred while getting the user");
                return StatusCode(500);
            }
        }
    }

}
---------------------------SLET DETTE*/