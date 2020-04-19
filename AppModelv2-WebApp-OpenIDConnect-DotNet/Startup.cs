using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Security.Claims;
using System.Web;
using System.Text;
using Microsoft.Identity.Client;

[assembly: OwinStartup(typeof(AppModelv2_WebApp_OpenIDConnect_DotNet.Startup))]

namespace AppModelv2_WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];

        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];


        // clientsecret
        string clientSecret = System.Configuration.ConfigurationManager.AppSettings["ClientSecret"];


        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        static string tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];

        // Authority is the URL for authority, composed by Microsoft identity platform endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        string authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["Authority"], tenant);

        string GraphResourceId = "https://graph.microsoft.com"; //"https://graph.windows.net";

        public static string idToken;
        public static string accessToken;

        /// <summary>
        /// Configure OWIN to use OpenIdConnect 
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOpenIdConnectAuthentication(
            new OpenIdConnectAuthenticationOptions
            {
                // Sets the ClientId, authority, RedirectUri as obtained from web.config
                ClientId = clientId,
                Authority = authority,
                RedirectUri = redirectUri,
                // PostLogoutRedirectUri is the page that users will be redirected to after sign-out. In this case, it is using the home page
                PostLogoutRedirectUri = redirectUri,
                Scope = "User.Read",//"openid email profile offline_access User.Read Mail.Send Files.ReadWrite", //OpenIdConnectScope.OpenIdProfile,
                // ResponseType is set to request the id_token - which contains basic information about the signed-in user
                //code refers to the Authorization Code
                // token refers to an Access Token or(access_token)
                // in the Authorization Code flow one switches the code for an access_token

                // https://stackoverflow.com/questions/29275477/openidconnect-response-type-confusion
                //https://stackoverflow.com/questions/25267831/asp-net-web-api-and-openid-connect-how-to-get-access-token-from-authorization-c
                //https://github.com/aspnet/Security/issues/1784
                //https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/tree/master/2-WebApp-graph-user/2-3-Multi-Tenant
                //https://www.andrewconnell.com/azure-ad-asp-net-mvc-walk-through-implementing-adal-owin

                //Azure AD Authentication Library for .NET
                //https://docs.microsoft.com/en-us/previous-versions/azure/jj573266(v=azure.100)?redirectedfrom=MSDN


                ResponseType = OpenIdConnectResponseType.CodeIdToken, // access token
                
                // ValidateIssuer set to false to allow personal and work accounts from any organization to sign in to your application
                // To only allow users from a single organizations, set ValidateIssuer to true and 'tenant' setting in web.config to the tenant name
                // To allow users from only a list of specific organizations, set ValidateIssuer to true and use ValidIssuers parameter 
                TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = false
                },
                // OpenIdConnectAuthenticationNotifications configures OWIN to send notification of failed authentications to OnAuthenticationFailed method
                Notifications = new OpenIdConnectAuthenticationNotifications
                {

                    /*
                    
                    AuthorizationCodeReceived = (context) => {
                        // get the OpenID Connect code passed from Azure AD on successful auth
                        //string code = context.Code;

                        //// create the app credentials & get reference to the user
                        //ClientCredential creds = new ClientCredential(SettingsHelper.ClientId, SettingsHelper.ClientSecret);
                        //string userObjectId = context.AuthenticationTicket.Identity.FindFirst(System.IdentityModel.Claims.ClaimTypes.NameIdentifier).Value;

                        //// use the ADAL to obtain access token & refresh token...
                        ////  save those in a persistent store...
                        //EfAdalTokenCache sampleCache = new EfAdalTokenCache(userObjectId);
                        //AuthenticationContext authContext = new AuthenticationContext(SettingsHelper.AzureADAuthority, sampleCache);

                        //// obtain access token for the AzureAD graph
                        //Uri redirectUri = new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path));
                        //AuthenticationResult authResult = authContext.AcquireTokenByAuthorizationCode(code, redirectUri, creds, SettingsHelper.AzureAdGraphResourceId);

                        //// successful auth
                        //return Task.FromResult(0);



                        
                        var code = context.Code;
                        ClientCredential credential = new ClientCredential(clientId, appKey);
                        string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
                        string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
                    AuthenticationContext authContext = new AuthenticationContext(string.Format("https://login.windows.net/{0}", tenantID),  new TokenCache()); //new EFADALTokenCache(signedInUserID));
                        AuthenticationResult result = authContext.AcquireTokenByAuthorizationCodeAsync(
                                    code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, graphResourceID);
                        
                        return Task.FromResult(0);
                        
                    
                        //var signedInUserId = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;

                        //// Acquire a Token for the Graph API and cache it.  In the TodoListController, we'll use the cache to acquire a token to the Todo List API
                        //string userObjectId = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
                        //ClientCredential clientCred = new ClientCredential(clientId, clientSecret);
                        //AuthenticationContext authContext = new AuthenticationContext(authority, new TokenCache(Encoding.Default.GetBytes(userObjectId)));
                        //AuthenticationResult authResult = authContext.AcquireTokenByAuthorizationCodeAsync(
                        //           context.Code, new Uri(context.RedirectUri), clientCred,  GraphResourceId);

                        //return Task.FromResult(0);
                    */
                    

                    AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                    AuthenticationFailed = OnAuthenticationFailed
                }
            }
        );
        }


        private Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {

            // good code
            // Acquire a Token for the Graph API and cache it.  In the TodoListController, we'll use the cache to acquire a token to the Todo List API
            string userObjectId = notification.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential clientCred = new Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential(clientId, clientSecret);
            
            AuthenticationContext authContext = new AuthenticationContext(authority, new Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache(Encoding.Default.GetBytes(userObjectId)));

            Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationResult authResult = authContext.AcquireTokenByAuthorizationCodeAsync(
                       notification.Code, new Uri(notification.RedirectUri), clientCred, GraphResourceId).Result;
            // decode token
            // https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens


            idToken = authResult.IdToken;
            accessToken = authResult.AccessToken;

            return Task.FromResult(0);
            

            //string authorizationCode = notification.Code;
            //ClientCredential clientCred = new ClientCredential(clientId, clientSecret);

            //AuthenticationResult tokenResult = notification.(authorizationCode, new Uri(notification.RedirectUri), clientCred);
            //return Task.FromResult(0);

            /*
            var code = notification.Code;
            string signedInUserID = notification.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;

            Microsoft.Identity.Client.TokenCache userTokenCache = new SessionTokenCache(
                signedInUserID,
                notification.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase).GetMsalCacheInstance();


            ConfidentialClientApplication cca = new ConfidentialClientApplicationBuilder(
                clientId,
                redirectUri,
                new Microsoft.Identity.Client.ClientCredential(clientSecret),
                userTokenCache,
                null);
            string[] scopes = graphScopes.Split(new char[] { ' ' });

            Microsoft.Identity.Client.AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, scopes);
            return Task.FromResult(0);
            */
        }

        /// <summary>
        /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
        }
    }
}
