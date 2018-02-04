# ASP.NET Core 2.0 Hmac Authentication 

This library is just for illustration. Be careful when you plan to use for production.

ASP.NET Core 2.0 port of https://github.com/ademcaglin/Security.HmacAuthentication/tree/master/tests/HmacTests which is based on http://bitoftech.net/2014/12/15/secure-asp-net-web-api-using-api-key-authentication-hmac-authentication/ and https://github.com/johnhidey/Hmac .

# How to use

Copy files in Security.HmacAuthentication/HmacAuthentication/ folder into your project and write following code in `Startup.cs`:
		
        public void ConfigureServices(IServiceCollection services)
        {
            //...
			services.AddAuthentication()
					.AddHmacAuth(cfg =>
					{
						cfg.AppId = "<app-id>"
						cfg.SecretKey = "<secret>";
						cfg.MaxRequestAgeInSeconds = 500;
					})
            //...
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            //...
            app.UseAuthentication();
            //...
         }

To call a API, use a `HttpClient`with a `DelegatingHandler`. An example can be found in
`Security.HmacAuthentication\HmacAuthentication\HmacDelegatingHandler.cs`.
