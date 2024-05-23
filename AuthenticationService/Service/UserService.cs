using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication.Models;
using Models;

namespace Authentication.Service
{
    public class UserService : IUserService
    {
        private readonly HttpClient _client;
        private readonly ILogger<UserService> _logger;

        public UserService(HttpClient client, ILogger<UserService> logger)
        {
            _client = client;
            _logger = logger;
        }

        public async Task<HttpResponseMessage> GetUserAsync(Guid _id)
        {
            var response = await _client.GetAsync($"api/user/getuser/{_id}");
            response.EnsureSuccessStatusCode();
            return response;
        }

        public async Task<bool> ValidateUser(LoginDTO user)
        {
            _logger.LogInformation("Validating user: {@User}", user);
            var userServiceResponse = await _client.PostAsJsonAsync("api/user/validate", user);
            userServiceResponse.EnsureSuccessStatusCode();
            return await userServiceResponse.Content.ReadFromJsonAsync<bool>();
        } 
    }
}