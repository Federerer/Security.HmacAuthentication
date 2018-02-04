using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace HmacTests
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMemoryCache();

            services.AddAuthentication()
               .AddHmacAuth(cfg =>
               {
                   cfg.SecretKey = "abc670d15a584f4baf0ba48455d3b155";
                   cfg.AppId = "jDEf7bMcJVFnqrPd599aSIbhC0IasxLBpGAJeW3Fzh4=";
               });
        }
        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);
            app.UseAuthentication();

            app.Map("/validate", builder =>
            {

                builder.UseAuthentication();
                builder.Run(async (context) =>
                {                    
                    var result = await context.AuthenticateAsync("Hmac");
                    
                    //it should be True
                    await context.Response.WriteAsync(result.Succeeded.ToString());
                });
            });

            app.Map("/replayattack", builder =>
            {
                builder.Run(async (context) =>
                {
                    var result = await context.AuthenticateAsync("Hmac");
                    //it should be True
                    await context.Response.WriteAsync(result.Succeeded.ToString());
                });
            });
        }
    }
}
