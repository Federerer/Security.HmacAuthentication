using Microsoft.AspNetCore.Authentication;

namespace Microsoft.AspNetCore.Builder
{
    public class HmacAuthenticationOptions : AuthenticationSchemeOptions
    {
        public long MaxRequestAgeInSeconds { get; set; } = 300;

        public string AppId { get; set; }

        public string SecretKey { get; set; }
    }
}
