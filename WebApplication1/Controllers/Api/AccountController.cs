using System;
using System.Linq;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using System.Web.Routing;
using Microsoft.Owin.Security;
using Pysco68.Owin.Authentication.Ntlm;

namespace WebApplication1.Controllers.Api
{
    [RoutePrefix("api/account")]
    public class AccountController : 
                 ApiController
    {
        [AllowAnonymous]
        [Route("ntlmlogin")]
        [HttpGet]
        public IHttpActionResult Ntlmlogin(string redirectUrl = null)
        {
            // see: http://davenport.sourceforge.net/ntlm.html#whatIsNtlm
            // create a login challenge if there's no user logged in
            if (User == null ||
                !User.Identity.IsAuthenticated)
            {
                var ap = new AuthenticationProperties() { RedirectUri = redirectUrl };
                var context = HttpContext.Current.GetOwinContext();
                context.Authentication.Challenge(ap, NtlmAuthenticationDefaults.AuthenticationType);
                return Unauthorized();
            }

            var values = Request.GetQueryNameValuePairs();
            if (values != null &&
                values.Any())
            {
                var d = values.ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
                if (d.ContainsKey("access_token"))
                    return Json(new { access_token = d["access_token"] });
            }

            return Json(new { access_token = "" }); 
        }
    }
}