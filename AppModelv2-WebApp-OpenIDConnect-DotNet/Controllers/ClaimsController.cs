using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using AuthenticationContext = Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext;

using Microsoft.Graph;
using Microsoft.Identity.Client;

using System.Configuration;
using PublicClientApplication = Microsoft.Graph.PublicClientApplication;
using Newtonsoft.Json.Linq;
using System.Text;
//using PublicClientApplication = Microsoft.Identity.Client.PublicClientApplication;

namespace AppModelv2_WebApp_OpenIDConnect_DotNet.Controllers
{
    public class Users
    {
        public string grant_type { get; set; }
        public string client_id { get; set; }

        public string client_secret { get; set; }
        public string resource { get; set; }

    }
    [Authorize]
    public class ClaimsController : Controller
    {
        /// <summary>
        /// Add user's claims to viewbag
        /// </summary>
        /// <returns></returns>
        public ActionResult Index()
        {
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            var groups = userClaims?.FindFirst("groups")?.Value;

            //You get the user’s first and last name below:
            ViewBag.Name = userClaims?.FindFirst("name")?.Value;

            // The 'preferred_username' claim can be used for showing the username
            ViewBag.Username = userClaims?.FindFirst("preferred_username")?.Value;

            // The subject/ NameIdentifier claim can be used to uniquely identify the user across the web
            ViewBag.Subject = userClaims?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            // TenantId is the unique Tenant Id - which represents an organization in Azure AD
            ViewBag.TenantId = userClaims?.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value;

            string userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            //string userObjectID = (User.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier"))?.Value;
            //AuthenticationContext authContext = new AuthenticationContext(Startup.Authority, new NaiveSessionCache(userObjectID, HttpContext.Session));
            //ClientCredential credential = new ClientCredential(Startup.ClientId, Startup.ClientSecret);
            //result = await authContext.AcquireTokenSilentAsync(Startup.GraphResourceId, credential, new UserIdentifier(userObjectID, UserIdentifierType.UniqueId));


            //var oidClaim = context.SecurityToken.Claims.FirstOrDefault(c => c.Type == "oid");
            //if (!string.IsNullOrWhiteSpace(oidClaim?.Value))
            //{
            //    var pagedCollection = await this.aadClient.Users.GetByObjectId(oidClaim.Value).MemberOf.ExecuteAsync();

            //    do
            //    {
            //        var directoryObjects = pagedCollection.CurrentPage.ToList();
            //        foreach (var directoryObject in directoryObjects)
            //        {
            //            var group = directoryObject as Group;
            //            if (group != null)
            //            {
            //                ((ClaimsIdentity)context.Ticket.Principal.Identity).AddClaim(new Claim(ClaimTypes.Role, group.DisplayName, ClaimValueTypes.String));
            //            }
            //        }
            //        pagedCollection = pagedCollection.MorePagesAvailable ? await pagedCollection.GetNextPageAsync() : null;
            //    }
            //    while (pagedCollection != null);
            //}


            //var groups = User.Claims.Where(c => c.Type == "groups").ToList();

            //return Ok(User.Claims.Where(claim => claim.Type == "groups").Select(c => new ClaimsViewModel() { Type = c.Type, Value = c.Value }));

            //IList<string> groupMembership = new List<string>();
            //try
            //{
            //    ActiveDirectoryClient activeDirectoryClient = ActiveDirectoryClient;
            //    IUser user = activeDirectoryClient.Users.Where(u => u.ObjectId == id).ExecuteSingleAsync().Result;
            //    var userFetcher = (IUserFetcher)user;

            //    IPagedCollection<IDirectoryObject> pagedCollection = userFetcher.MemberOf.ExecuteAsync().Result;
            //    do
            //    {
            //        List<IDirectoryObject> directoryObjects = pagedCollection.CurrentPage.ToList();
            //        foreach (IDirectoryObject directoryObject in directoryObjects)
            //        {
            //            if (directoryObject is Group)
            //            {
            //                var group = directoryObject as Group;
            //                groupMembership.Add(group.DisplayName);
            //            }
            //        }
            //        pagedCollection = pagedCollection.GetNextPageAsync().Result;
            //    } while (pagedCollection != null);

            //}
            //catch (Exception e)
            //{
            //    ExceptionHandler.HandleException(e);
            //    throw e;
            //}

            //https://graph.microsoft.com/v1.0/me/memberOf
            Task<HttpResponseMessage> response = GetDirectoryUsers(Startup.accessToken);


            //GetDataAsync().GetAwaiter().GetResult();


            return View();
        }

        /*
        [Authorize]
        public async Task UserProfile()
        {
            string tenantId = ClaimsPrincipal.Current.FindFirst(TenantIdClaimType).Value;

            // Get a token for calling the Azure Active Directory Graph
            AuthenticationContext authContext = new AuthenticationContext(String.Format(CultureInfo.InvariantCulture, LoginUrl, tenantId));
            ClientCredential credential = new ClientCredential(AppPrincipalId, AppKey);
            AuthenticationResult assertionCredential = authContext.AcquireTokenAsync(GraphUrl, credential);
            string authHeader = assertionCredential.CreateAuthorizationHeader();
            string requestUrl = String.Format(
                CultureInfo.InvariantCulture,
                GraphUserUrl,
                HttpUtility.UrlEncode(tenantId),
                HttpUtility.UrlEncode(User.Identity.Name));

            HttpClient client = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.TryAddWithoutValidation("Authorization", authHeader);
            HttpResponseMessage response = await client.SendAsync(request);
            string responseString = await response.Content.ReadAsStringAsync();

            // UserProfile profile = JsonConvert.DeserializeObject<UserProfile>(responseString);

            return View();
        }
        */
        [Authorize]
        public  async Task<HttpResponseMessage> GetDirectoryUsers(string graphToken)
        {
            //HttpClient client = new HttpClient();
            //client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

            ////string requestUrl = "https://graph.microsoft.com/v1.0/groups?$top=2&$filter=displayName eq '" + displayName + "'&$expand=Members";

            ////string requestUrl = "https://graph.microsoft.com/v1.0/me/memberOf";

            string requestUrl = "https://graph.microsoft.com/v1.0/users";

            //var request = new HttpRequestMessage(new HttpMethod("GET"), requestUrl);
            //var response = await client.SendAsync(request);
            //// string responseString = await response.Content.ReadAsStringAsync();

            //return response;

            //Task<HttpResponseMessage> accessToken = GetAccessToken();


            sendPost();


            //using (var client = new HttpClient())
            //{
            //    using (var request = new HttpRequestMessage(HttpMethod.Get, requestUrl))
            //    {
            //        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

            //        return client.SendAsync(request).Result;
            //        //using (var response = await client.SendAsync(request))
            //        //{
            //        //    if (response.IsSuccessStatusCode)
            //        //    {
            //        //        var json = JObject.Parse(await response.Content.ReadAsStringAsync());
            //        //        return response;
            //        //    }
            //        //    else 
            //        //        return null;
            //        //}
            //    }
            //}
            return null;

        }

        [Authorize]
        public async  Task<HttpResponseMessage> GetAccessToken()
        {
            string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];
            // clientsecret
            string clientSecret = System.Configuration.ConfigurationManager.AppSettings["ClientSecret"];

            // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
            string tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];

            string requestUrl = "https://login.microsoftonline.com/cdd071d0-805d-4b10-bac9-ee8225b4cbdc/oauth2/token?grant_type=client_credentials&" +
                                 "client_id=9ab33241-e1e4-4eaa-ad38-d1e1906da807&" +
                                 "client_secret=qJS.39C:W-hA8-YiDFw57M2?=zGSciKU&" +
                                 "resourse=https://graph.microsoft.com";


            var users = new Users();
            users.grant_type = "client_credentials";
            users.client_id = "9ab33241-e1e4-4eaa-ad38-d1e1906da807";
            users.client_secret = "qJS.39C:W-hA8-YiDFw57M2?=zGSciKU";
            users.resource = "https://graph.microsoft.com";

            

            var json = JsonConvert.SerializeObject(users);
            HttpContent data = new StringContent(json, Encoding.UTF8, "application/json");//"application/x-www-form-urlencoded");

            var url = "https://login.microsoftonline.com/cdd071d0-805d-4b10-bac9-ee8225b4cbdc/oauth2/token";
            var client = new HttpClient();

            var response = await client.PostAsync(url, data);

            string result = response.Content.ReadAsStringAsync().Result;
            Console.WriteLine(result);




            return response;

        }

        public async Task<bool> sendPost()
        {
            


            Dictionary<string, string> pairs = new Dictionary<string, string>();
            pairs.Add("grant_type", "client_credentials");
            pairs.Add("client_id", "9ab33241-e1e4-4eaa-ad38-d1e1906da807");
            pairs.Add("client_secret", "qJS.39C:W-hA8-YiDFw57M2?=zGSciKU");
            pairs.Add("resource", "https://graph.microsoft.com");


            FormUrlEncodedContent formContent =
                new FormUrlEncodedContent(pairs);
            string url = "https://login.microsoftonline.com/cdd071d0-805d-4b10-bac9-ee8225b4cbdc/oauth2/token";

            HttpClient client = new HttpClient();
            var response = await client.PostAsync(url, formContent);


            //var response = await client.PostAsync("api/Inspections/UpdateInspection", stringContent);
            if (response.IsSuccessStatusCode)
            {
                var jsonresult = response.Content.ReadAsStringAsync().Result;

                
                string graphToken = "";
                using (var client1 = new HttpClient())
                {
                    string requestUrl = "https://graph.microsoft.com/v1.0/users";
                    using (var request = new HttpRequestMessage(HttpMethod.Get, requestUrl))
                    {
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", graphToken);

                        HttpResponseMessage result = client1.SendAsync(request).Result;
                        
                    }
                }

            }
            return true;
        }


        //public static async Task GetDataAsync()
        //{
        //    Console.WriteLine("Display user details");

        //    //PublicClientApplication clientApp = new PublicClientApplication(ConfigurationManager.AppSettings["clientId"].ToString());

        //    Microsoft.Identity.Client.PublicClientApplication clientApp = new Microsoft.Identity.Client.PublicClientApplication(ConfigurationManager.AppSettings["clientId"].ToString());


        //    GraphServiceClient graphClient = new GraphServiceClient(
        //                "https://graph.microsoft.com/v1.0",
        //                new DelegateAuthenticationProvider(
        //                    async (requestMessage) =>
        //                    {
        //                        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("bearer", await GetTokenAsync(clientApp));
        //                    }));

        //    var currentUser = await graphClient.Me.Request().GetAsync();
        //    Console.WriteLine(currentUser.DisplayName);
        //}

        //public static async Task<string> GetTokenAsync(Microsoft.Identity.Client.PublicClientApplication clientApp)
        //{
        //    //need to pass scope of activity to get token
        //    string[] Scopes = { "User.Read" };
        //    string token = null;

        //    Microsoft.Identity.Client.AuthenticationResult authResult = await clientApp.AcquireTokenAsync(Scopes);
        //    token = authResult.AccessToken;

        //    return token;
        //}


    }
}