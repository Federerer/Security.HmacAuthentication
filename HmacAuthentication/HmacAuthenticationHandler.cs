using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.Hmac
{
    internal class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
    {
        private readonly IMemoryCache memoryCache;

        public HmacAuthenticationHandler(
            IOptionsMonitor<HmacAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IMemoryCache memoryCache) : base(options, logger, encoder, clock)
        {
            this.memoryCache = memoryCache;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var authorization = Request.Headers["authorization"];

            if (string.IsNullOrEmpty(authorization))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var valid = validate(Request);

            if (valid)
            {
                var principal = new ClaimsPrincipal(new ClaimsIdentity("HMAC"));
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), HmacAuthenticationDefaults.AuthenticationScheme);
                return Task.FromResult(AuthenticateResult.Success(ticket));
            }

            return Task.FromResult(AuthenticateResult.Fail("Authentication failed"));
        }

        private bool validate(HttpRequest request)
        {
            var header = request.Headers["authorization"];
            var authenticationHeader = AuthenticationHeaderValue.Parse(header);

            if (HmacAuthenticationDefaults.AuthenticationScheme.Equals(authenticationHeader.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                var rawAuthenticationHeader = authenticationHeader.Parameter;
                var authenticationHeaderArray = getAuthenticationValues(rawAuthenticationHeader);

                if (authenticationHeaderArray != null)
                {
                    var appId = authenticationHeaderArray[0];
                    var incomingBase64Signature = authenticationHeaderArray[1];
                    var nonce = authenticationHeaderArray[2];
                    var requestTimeStamp = authenticationHeaderArray[3];

                    return isValidRequest(request, appId, incomingBase64Signature, nonce, requestTimeStamp);
                }
            }

            return false;
        }

        private bool isValidRequest(HttpRequest req, string appId, string incomingBase64Signature, string nonce, string requestTimeStamp)
        {
            string requestContentBase64String = "";
            var absoluteUri = string.Concat(
                        req.Scheme,
                        "://",
                        req.Host.ToUriComponent(),
                        req.PathBase.ToUriComponent(),
                        req.Path.ToUriComponent(),
                        req.QueryString.ToUriComponent());
            string requestUri = WebUtility.UrlEncode(absoluteUri).ToLowerInvariant();
            string requestHttpMethod = req.Method;

            if (Options.AppId != appId)
            {
                return false;
            }

            var sharedKey = Options.SecretKey;

            if (isReplayRequest(nonce, requestTimeStamp))
            {
                return false;
            }
            
            req.EnableRewind();
            byte[] hash = computeHash(req.Body);
            req.Body.Seek(0, SeekOrigin.Begin);

            if (hash != null)
            {
                requestContentBase64String = Convert.ToBase64String(hash);
            }

            string data = String.Format("{0}{1}{2}{3}{4}{5}", appId, requestHttpMethod, requestUri, requestTimeStamp, nonce, requestContentBase64String);

            var secretKeyBytes = Convert.FromBase64String(sharedKey);

            byte[] signature = Encoding.UTF8.GetBytes(data);

            using (HMACSHA256 hmac = new HMACSHA256(secretKeyBytes))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);
                return (incomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal));
            }
        }

        private string[] getAuthenticationValues(string rawAuthenticationHeader)
        {
            var credArray = rawAuthenticationHeader.Split(':');

            if (credArray.Length == 4)
            {
                return credArray;
            }
            else
            {
                return null;
            }
        }

        private bool isReplayRequest(string nonce, string requestTimeStamp)
        {
            var nonceInMemory = memoryCache.Get(nonce);
            if (nonceInMemory != null)
            {
                return true;
            }

            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan currentTs = DateTime.UtcNow - epochStart;

            var serverTotalSeconds = Convert.ToInt64(currentTs.TotalSeconds);
            var requestTotalSeconds = Convert.ToInt64(requestTimeStamp);
            var diff = (serverTotalSeconds - requestTotalSeconds);

            if (Math.Abs(diff) > Options.MaxRequestAgeInSeconds)
            {
                return true;
            }

            memoryCache.Set(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(Options.MaxRequestAgeInSeconds));
            return false;
        }

        private byte[] computeHash(Stream body)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = null;
                var content = readFully(body);
                if (content.Length != 0)
                {
                    hash = md5.ComputeHash(content);
                }
                return hash;
            }
        }

        private byte[] readFully(Stream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }
    }
}
