using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;


namespace OpenLink
{
    public class Oidc 
  {
#region Private Fields
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;
        private RsaSecurityKey _privateRSAKey;
        private RsaSecurityKey _publicRSAKey;

        private int DEFAULT_MAX_AGE = 3600;
        private int stateLength = 16;
        private bool _hasGeneratedKeys = false;
        private string _identityProviderUrl = string.Empty;
        private HttpClient _client;
        private string _appName;
        private string _appScopes = "openid profile"; // offline_access webid";
        private bool _useDebug = true;
        private string[] _redirectUris;
        private EndpointInfo _endpointInfo;

        private string _grant_types = "implicit";
        private string _response_types = "id_token token";
        private string _alg = "RS256";
        // private values
        private string _clientId;
        private string _clientSecret;
        private string _clientIdToken;
        private string _clientAccessToken;
        private string _clientTokenType;
        private string _clientState;
        private string _clientNonce;
        private IList<SecurityKey>? _jwks;
        private string _client_webId;

        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
#endregion

#region Public Properties
        public bool HasGeneratedKeys => _hasGeneratedKeys;
        public string IdentityProviderUrl => _identityProviderUrl;
        public bool UseDebug => _useDebug;
        public string Access_Token => _clientAccessToken;
        public string Client_Token => _clientIdToken;
        public string Client_WebID => _client_webId;
#endregion

#region Constructors
        public Oidc()
        {
            _client = new HttpClient();
#if SelfSignedCertServer
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.UseDefaultCredentials = true;
            handler.ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) =>
                {
                    return true;
                };

            _client = new HttpClient(handler);
#endif
        }

        public Oidc(string identityProvider) : this()
        {
            _identityProviderUrl = identityProvider;
        }
#endregion

#region Public Methods
        public void SetDebug(bool useDebug)
        {
            _useDebug = useDebug;
        }

        public string GetLoginUrl(string redirectUrl) 
        {
            var _params = new System.Collections.Generic.Dictionary<string, string>();

            _clientState = CreateUniqueId(stateLength);
            _clientNonce = CreateUniqueId(stateLength);

            _params.Add("response_type", _response_types);
            _params.Add("scope", _appScopes);
            _params.Add("redirect_uri", redirectUrl);

            _params.Add("client_id", _clientId);
            _params.Add("display", "page");

            _params.Add("state", _clientState); 
            _params.Add("nonce", _clientNonce);

            // gen session keys
            GenerateKeys();

            if (_endpointInfo!=null && _endpointInfo.request_parameter_supported)
            {
                //encode Request Params
                _params = EncodeRequestParams(_params);
            }

            string auth_endpoint = _endpointInfo != null ? _endpointInfo.authorization_endpoint : "";
            var url = BuildUrl(auth_endpoint, _params);
            return url;
        }

        public void SetAccessAndIdToken(string queryString)
        {
            var data = HttpUtility.ParseQueryString(queryString);
            var id_token = data["id_token"];
            var access_token = data["access_token"];
            var token_type = data["token_type"];

            var state = data["state"];
            var error = data["error"];

            if (error != null)
            {
                var error_desc = data["error_description"];
                var error_uri = data["error_uri"];
                throw new Exception($"Error:{error} : ${error_desc} State:{state}");
            }

            if (state == null || !state.Equals(_clientState))
                throw new Exception("Missing state parameter in authentication response");


            if (id_token == null)
                throw new Exception("Missing id_token in authentication response");

            if (access_token == null)
                throw new Exception("Missing access_token in authentication response");

            //validate id_token
            var jwt_id = new JwtSecurityToken(id_token);

            if (jwt_id.Issuer != _identityProviderUrl)
                throw new Exception("Mismatching issuer in ID Token");

            object nonce;
            bool rc = jwt_id.Payload.TryGetValue("nonce", out nonce);
            if (rc && nonce != null && !nonce.Equals(_clientNonce))
                throw new Exception("Mismatching nonce in ID Token");


            // validate audience includes this relying party
            var aud_lst = jwt_id.Audiences;
            object azp;
            rc = jwt_id.Payload.TryGetValue("azp", out azp);

            // validate authorized party is present if required
            if (aud_lst.IsNullOrEmpty() && azp == null )
                throw new Exception("Missing azp claim in id_token");

            // validate authorized party is this relying party
            if (rc && azp != null && !_clientId.Equals(azp))
                throw new Exception("Mismatching azp in id_token");

            var tokenHandler = new JwtSecurityTokenHandler();
            // we don't actually need to do this, this is just a sanity check
            var validationParameters = new TokenValidationParameters
            {
                ClockSkew = TimeSpan.FromMinutes(5),
                IssuerSigningKeys = _jwks,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidAudience =  _clientId,
                ValidateIssuer = true,
                ValidIssuer = _identityProviderUrl,
            };

            SecurityToken token;
            tokenHandler.ValidateToken(id_token, validationParameters, out token);

            _client_webId = jwt_id.Payload.Sub;
            _clientAccessToken = access_token;
            _clientIdToken = id_token;
            _clientTokenType = token_type;
        }

        public Dictionary<string,string> EncodeRequestParams(Dictionary<string, string> _params)
        {
            var payload = new JwtPayload();
            var header = new JwtHeader();

            var excludeParams = new List<string> { "scope", "client_id", "response_type", "state" };

            foreach (var kv in _params.Where(kv => !excludeParams.Contains(kv.Key)))
            {
                payload.AddClaim(new Claim(kv.Key, kv.Value));
            }

            var pubKey = GetPublicJsonWebKey();
            payload.Add("key", pubKey);
            header.Add("alg", "none");

            var jwt = new JwtSecurityToken(header, payload);
            var text = new JwtSecurityTokenHandler().WriteToken(jwt);

            var newParams = new Dictionary<string, string>(_params.Where(kv => excludeParams.Contains(kv.Key)));
            newParams.Add("request", text);

            return newParams;
        }


        public string CreatePopToken(string url)
        {
            if (string.IsNullOrEmpty(_clientIdToken))
                throw new Exception("Cannot issue PoPToken - missing id token");

            var issuer = new Uri(_identityProviderUrl);
            var cmd_url = new Uri(url);

            if (!(cmd_url.Host.Equals(issuer.Host) || cmd_url.Host.EndsWith(issuer.Host)))
                return null;

            var sessionKey = GetPrivateJsonWebKey();

            var payload = new JwtPayload();
            var header = new JwtHeader();

            payload.AddClaim(new Claim("id_token", _clientIdToken));
            payload.AddClaim(new Claim("token_type", "pop"));

            var dt_now = DateTime.UtcNow;
            var iat = ComputeCurrentIat(dt_now);
            payload.AddClaim(new Claim("iat", iat.ToString(), ClaimValueTypes.Integer));

            header.Add("alg", _alg);

            var sign_cred = new SigningCredentials(sessionKey, _alg);

            var jwt = new JwtSecurityToken(_clientId, cmd_url.GetLeftPart(UriPartial.Authority), payload.Claims, dt_now, dt_now.AddSeconds(DEFAULT_MAX_AGE), sign_cred);
            var text = new JwtSecurityTokenHandler().WriteToken(jwt);

            return text;
        }


        private int ComputeCurrentIat(DateTime issueTime)
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            return (int)issueTime.Subtract(utc0).TotalSeconds;
        }

        public string BuildUrl(string endpoint, Dictionary<string,string> _params)
        {
            var query = HttpUtility.ParseQueryString(string.Empty);
            foreach (var kv in _params)
                query.Add(kv.Key, kv.Value);

            return $@"{endpoint}?{query.ToString()}";
        }


        public void GenerateKeys()
        {
            var rsa = RSA.Create();

            _publicKey = rsa.ExportParameters(false);
            _privateKey = rsa.ExportParameters(true);

            _privateRSAKey = new RsaSecurityKey(_privateKey);
            _publicRSAKey = new RsaSecurityKey(_publicKey);

            _hasGeneratedKeys = true;
        }

        public JsonWebKey GetPrivateJsonWebKey()
        {
            if (!HasGeneratedKeys)
            {
                GenerateKeys();
            }

            var key = JsonWebKeyConverter.ConvertFromRSASecurityKey(_privateRSAKey);
            key.AdditionalData.Add("alg", _alg);
            return key;
        }

        public JsonWebKey GetPublicJsonWebKey()
        {
            if (!HasGeneratedKeys)
            {
                GenerateKeys();
            }

            var key = JsonWebKeyConverter.ConvertFromRSASecurityKey(_publicRSAKey);
            key.AdditionalData.Add("alg", _alg);
            key.AdditionalData.Add("key_ops", new List<string>() { "verify" });
            return key;
        }


        public async Task RegisterAppAsync(string identityProvider, string[] redirectUris, string appName)
        {
            _identityProviderUrl = identityProvider;
            await GetConfigurationAsync();  //rp.discover()
            await GetConfigurationKeys();
            await RegisterAppAsync(redirectUris, appName); //rp.register
        }

        public async Task<bool> RegisterAppAsync(string[] redirectUris, string appName)
        {
            if (string.IsNullOrEmpty(_appName))
            {
                _appName = appName;
            }

            _redirectUris = redirectUris;

            string url = _endpointInfo.registration_endpoint;
            string issuer = _endpointInfo.issuer;

            var contentBuilder = new StringBuilder();
            contentBuilder.Append("{");
            contentBuilder.Append(@"""application_type"": ""web"",");
            contentBuilder.Append(@"""redirect_uris"":[");

            if (redirectUris.Length == 1)
            {
                contentBuilder.Append($@"""{redirectUris.First()}""");
            }
            else
            {
                foreach (var uri in redirectUris)
                {
                    contentBuilder.Append($@"""{uri}""");
                    if (redirectUris.Last() != uri)
                    {
                        contentBuilder.Append(",");
                    }
                }
            }
            contentBuilder.Append("],");
            
            contentBuilder.Append(@"""post_logout_redirect_uris"":[");

            if (redirectUris.Length == 1)
            {
                contentBuilder.Append($@"""{redirectUris.First()}""");
            }
            else
            {
                foreach (var uri in redirectUris)
                {
                    contentBuilder.Append($@"""{uri}""");
                    if (redirectUris.Last() != uri)
                    {
                        contentBuilder.Append(",");
                    }
                }
            }
            contentBuilder.Append("],");
            //            contentBuilder.Append($@"""client_name"": ""{appName}"",");
            contentBuilder.Append($@"""scopes"": ""{_appScopes}"",");

            contentBuilder.Append($@"""grant_types"": [""{_grant_types}""],");
            contentBuilder.Append($@"""issuer"": ""{issuer}"",");
            contentBuilder.Append($@"""response_types"": [""{_response_types}""]");

            contentBuilder.Append("}");

            var stringContent = new StringContent(contentBuilder.ToString(), Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = stringContent;
            var response = await _client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                var item = JsonConvert.DeserializeObject<RegisterData>(data);
                if (item is not null)
                {
                    _clientId = item.client_id;
                    _clientSecret = item.client_secret;
                    return true;
                }
            }
            return false;
        }

        public async Task<bool> Logout(string redirect_uri)
        {
            if (_client != null && _endpointInfo != null && !string.IsNullOrEmpty(_endpointInfo.end_session_endpoint))
            {
                var _params = new Dictionary<string, string>();
                _params.Add("id_token_hint", _clientIdToken);
                _params.Add("post_logout_redirect_uri", redirect_uri);
                _params.Add("state", _clientState);
                var url = BuildUrl(_endpointInfo.end_session_endpoint, _params);

                if (_client is not null)
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, url);
                    var response = await _client.SendAsync(request);
                    var rc = response.IsSuccessStatusCode;
                    if (rc)
                    {
                        Clear();
                        return true;
                    }
                }
                return false;
            }
            else
                return false;
        }
        public string GetLogoutUrl(string redirect_uri)
        {
            if (_client != null && _endpointInfo != null && !string.IsNullOrEmpty(_endpointInfo.end_session_endpoint))
            {
                var _params = new System.Collections.Generic.Dictionary<string, string>();
                _params.Add("id_token_hint", _clientIdToken);
                _params.Add("post_logout_redirect_uri", redirect_uri);
                _params.Add("state", _clientState);
                var url = BuildUrl(_endpointInfo.end_session_endpoint, _params);
                return url;
            }
            else
                return null;
        }
#endregion


#region Private Methods
        private void DebugOut(string item)
        {
            if (_useDebug)
            {
                Console.WriteLine(item);
                Debug.WriteLine(item);
            }
        }

        private void Clear()
        {
            _privateRSAKey = null;
            _publicRSAKey = null;
            _hasGeneratedKeys = false;
            _clientSecret = null;
            _clientIdToken = null;
            _clientAccessToken = null;
            _client_webId = null;
        }

        private async Task GetConfigurationAsync()
        {
            if (!string.IsNullOrEmpty(_identityProviderUrl))
            {
                if (_client is not null)
                {
                    var response = _client.GetAsync(_identityProviderUrl + "/.well-known/openid-configuration");
                    var data = await response.Result.Content.ReadAsStringAsync();
                    var item = JsonConvert.DeserializeObject<EndpointInfo>(data);
                    if (item is not null)
                    {
                        _endpointInfo = item;
                    }
                }
            }
        }

        private async Task GetConfigurationKeys()
        {
            if (!string.IsNullOrEmpty(_endpointInfo.jwks_uri))
            {
                if (_client is not null)
                {
                    var response = _client.GetAsync(_endpointInfo.jwks_uri);
                    var data = await response.Result.Content.ReadAsStringAsync();
                    _jwks = new JsonWebKeySet(data).GetSigningKeys();
                }
            }
        }

        private string StringSha256(string s)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] sbytes = Encoding.UTF8.GetBytes(s);
                return Convert.ToBase64String(sha256.ComputeHash(sbytes));
            }
        }



        private string CreateUniqueId(int length = 32)
        {
            var bytes = new byte[length];
            Rng.GetBytes(bytes);
            return Base64Url_Encode(bytes);
        }

        private string Base64Url_Encode(byte[] arg)
        {
            var s = Convert.ToBase64String(arg);

            s = s.Split('=')[0];
            s = s.Replace('+', '-');
            s = s.Replace('/', '_');

            return s;
        }

#endregion

    }
}
