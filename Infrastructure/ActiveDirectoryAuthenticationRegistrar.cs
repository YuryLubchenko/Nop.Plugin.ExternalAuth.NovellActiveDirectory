using Microsoft.AspNetCore.Authentication;
using Nop.Services.Authentication.External;

namespace Nop.Plugin.ExternalAuth.NovellActiveDirectory.Infrastructure
{
    public class ActiveDirectoryAuthenticationRegistrar : IExternalAuthenticationRegistrar
    {
        public void Configure(AuthenticationBuilder builder)
        {
        }
    }
}