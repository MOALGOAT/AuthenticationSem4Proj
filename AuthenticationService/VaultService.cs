using System;
using System.Net.Http;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using Microsoft.Extensions.Configuration;

namespace Authentication
{
    public class VaultService
    {
        private readonly IVaultClient _vaultClient;
        private readonly IConfiguration _config;

        public VaultService(IConfiguration _config) 
        {
            var EndPoint = _config["vaultConnectionString"];
            var httpClientHandler = new HttpClientHandler();

            // Tillad forbindelser til usikre HTTP-endepunkter
            httpClientHandler.ServerCertificateCustomValidationCallback =
                (message, cert, chain, sslPolicyErrors) => true;


            IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

            var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
            {
                Namespace = "",
                MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
                {
                    BaseAddress = new Uri(EndPoint)
                }
            };
            
            _vaultClient = new VaultClient(vaultClientSettings);
        }  
        
        public async Task<string> GetSecretAsync(string path, string key)
        {
            var kv2Secret = await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: path, mountPoint: "secret");

            return kv2Secret.Data.Data[key].ToString();
        }
    }
}
