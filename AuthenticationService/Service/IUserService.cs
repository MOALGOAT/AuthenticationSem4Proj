using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication.Models;

namespace Authentication.Service
{
    public interface IUserService
    {
        Task<HttpResponseMessage> GetUserAsync(Guid _id);
        Task<bool> ValidateUser(User user);
    }
}