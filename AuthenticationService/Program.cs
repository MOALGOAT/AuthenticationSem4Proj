using System;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Authentication;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using NLog;
using NLog.Web;
using Authentication.Service;
using Authentication.Models;


var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings()
    .GetCurrentClassLogger();
logger.Debug("init main");

try
{
    var builder = WebApplication.CreateBuilder(args);
    var configuration = builder.Configuration;

    var vaultService = new VaultService(configuration);

    string mySecret = await vaultService.GetSecretAsync("secrets", "SecretKey");
    string myIssuer = await vaultService.GetSecretAsync("secrets", "IssuerKey");
    configuration["SecretKey"] = mySecret;
    configuration["IssuerKey"] = myIssuer;
    
    Console.WriteLine("heyhey" + myIssuer);
    Console.WriteLine("asdad" + mySecret);

    builder.Services.AddTransient<VaultService>();
    builder.Services.AddTransient<MongoDBContext>();
    builder.Services.AddTransient<IUserInterface, UserMongoDBService>();
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })

    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = myIssuer,
            ValidAudience = "http://localhost",
            IssuerSigningKey =
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
        };
    });

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowOrigin", builder =>
        {
            builder.AllowAnyHeader()
                   .AllowAnyMethod();
        });
    });

    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();
    app.UseCors("AllowOrigin");
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    NLog.LogManager.Shutdown();
}
