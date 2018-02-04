using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Hmac;
using System;

namespace Microsoft.AspNetCore.Builder
{
    public static class HmacAppBuilderExtension
    {
        public static AuthenticationBuilder AddHmacAuth(
            this AuthenticationBuilder builder,
            Action<HmacAuthenticationOptions> configureOptions)
        {
            return builder.AddScheme<HmacAuthenticationOptions, HmacAuthenticationHandler>(
                HmacAuthenticationDefaults.AuthenticationScheme,
                HmacAuthenticationDefaults.AuthenticationScheme,
                configureOptions);
        }
    }
}
