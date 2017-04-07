using System;
using Microsoft.AspNet.Identity;
using System.Collections.Generic;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using System.Security.Claims;
using Microsoft.Owin.Security.Google;
using Owin;
using WebApplication1.Models;
using System.Threading.Tasks;
using Pysco68.Owin.Authentication.Ntlm;
using Microsoft.Owin.Security;
//using Autofac.Features.OwnedInstances;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;

namespace WebApplication1
{
    public class NtlmAuthOptions :
                 NtlmAuthenticationOptions
    {
        public string DomainName { get; set; }
        public TimeSpan ExpiryPeriod { get; set; }
        //public Func<Owned<AppAuthManager>> AppAuthFactory { get; set; }
        public OAuthAuthorizationServerOptions Options { get; set; }
    }

    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationTypes.ApplicationCookie);

            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/account/ntlmlogin"),
                ReturnUrlParameter = "ReturnUrl",
                Provider = new CookieAuthenticationProvider
                {
                    OnApplyRedirect = ctx => {
                        if (!ctx.Request.IsNtlmAuthenticationCallback())
                        {
                            ctx.Response.Redirect(ctx.RedirectUri);
                        }
                    }
                }
            });

            var oauthServerOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = new TimeSpan(1, 0, 0),
                ApplicationCanDisplayErrors = true,
                AllowInsecureHttp = true,
                Provider = new OAuthAuthorizationServerProvider()
            };
            app.UseOAuthBearerTokens(oauthServerOptions);

            app.UseNtlmAuthentication(new NtlmAuthOptions()
            {
                DomainName = Environment.MachineName, // test only, my machinename (domain)
                ExpiryPeriod = new TimeSpan(1,0,0),
                //AppAuthFactory = _appAuthFactory,
                Options = oauthServerOptions,
                OnCreateIdentity = (windowsIdentity, authOptions, request/*, properties*/) => {
                    var options = authOptions as NtlmAuthOptions;
                    var parts = windowsIdentity.Name.Split(new[] { '\\' }, 2);
                    string username = parts.Length == 1 ? parts[0] : parts[parts.Length - 1];
                    string domainname = parts.Length == 1 ? null : parts[parts.Length - 2];
                    if (domainname == null ||
                        !domainname.Equals(options.DomainName, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                    //var user = appAuthManager.Value.FindUserByName(username);
                    var user = new ApplicationUser
                        {
                            Id = "1",
                            UserName = username
                    };

                    var claims = new List<Claim> {
                        new Claim(ClaimTypes.NameIdentifier, user.Id),
                        new Claim(ClaimTypes.Name, user.UserName)
                    };

                    //var roles = appAuthManager.Value.UserRoles(user.Id);
                    //claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

                    //var accessRights = appAuthManager.Value.UserAccessRights(user.Id);
                    //claims.AddRange(accessRights.Select(accessRight => new Claim(ClaimTypes.UserData, accessRight)));

                    // bearer token
                    var oauthIdentity = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);

                    // see: http://katanaproject.codeplex.com/SourceControl/latest#src/Microsoft.Owin.Security.OAuth/OAuthAuthorizationServerMiddleware.cs
                    var ticket = new AuthenticationTicket(oauthIdentity, new AuthenticationProperties(new Dictionary<string, string> {
                        {"userId", user.Id},
                        {"userName", user.UserName}
                    }));
                    var protector = app.CreateDataProtector(typeof(OAuthAuthorizationServerMiddleware).Namespace, "Access_Token", "v1");
                    var tdf = new TicketDataFormat(protector);
                    var access_token = tdf.Protect(ticket);

                    // return the token as a query parameter of the redirectUrl
                    //properties.RedirectUri += $"?access_token={access_token}";
                    //properties.ExpiresUtc = DateTime.UtcNow.Add(options.ExpiryPeriod);
                    //properties.IsPersistent = true;
                    //properties.AllowRefresh = true;

                    // cookies
                    var identity = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);
                    return identity;
                }
            });
        }
    }
}