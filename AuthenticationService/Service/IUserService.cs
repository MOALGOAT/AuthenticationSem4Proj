using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication.Models;
using Models;

namespace Authentication.Service
{
    public interface IUserService
    {
        //Task<HttpResponseMessage> GetUserAsync(Guid _id) SLET DETTE;
        Task<User> ValidateUser(LoginDTO user);
    }
}