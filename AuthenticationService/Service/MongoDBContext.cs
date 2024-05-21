using MongoDB.Driver;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;


namespace Authentication.Service
{
    public class MongoDBContext
    {
        private readonly IMongoDatabase _database;

        public MongoDBContext(ILogger<MongoDBContext> iLogger, IConfiguration configuration)
            {
                var connectionString = configuration["ConnectionString"];
                var databaseName = configuration["DatabaseName"]; 
                
                iLogger.LogInformation($"Connection string: {connectionString}");
                iLogger.LogInformation($"Database name: {databaseName}");
                
                var client = new MongoClient(connectionString);
                _database = client.GetDatabase(databaseName);
            }

        public IMongoCollection<T> GetCollection<T>(string collectionName)
            {
                return _database.GetCollection<T>(collectionName);
            }
    }
}
