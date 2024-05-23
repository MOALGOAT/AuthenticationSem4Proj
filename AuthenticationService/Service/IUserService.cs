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
        Task<HttpResponseMessage> GetUserAsync(Guid _id);
        Task<bool> ValidateUser(LoginDTO user); // lav så den returnerer en bruger så vi kan fiske rolle ud og bruge i login validate
    }
}