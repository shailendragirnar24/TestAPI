using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Text;

namespace GitHubAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly IHttpClientFactory _httpClientFactory;

        public AuthController(IConfiguration config, IHttpClientFactory httpClientFactory)
        {
            _config = config;
            _httpClientFactory = httpClientFactory;
        }
        // Step 1: Redirect user to GitHub login
        [HttpGet("login")]
        public IActionResult Login()
        {
            var clientId = _config["GitHub:ClientId"];
            var redirectUrl = _config["Jwt:Issuer"] + "/api/auth/callback";

            var githubLoginUrl = $"https://github.com/login/oauth/authorize?client_id={clientId}&redirect_uri={redirectUrl}&scope=user";
            return Redirect(githubLoginUrl);

        }


        [HttpGet("callback")]
        public async Task<IActionResult> Callback([FromQuery] string code)
        {
            if (string.IsNullOrEmpty(code)) return BadRequest("Authorization code is missing.");

            var client = _httpClientFactory.CreateClient();

            // 1. Exchange the code for a GitHub Access Token
            var tokenRequest = new Dictionary<string, string>
                {
                    { "client_id", _config["GitHub:ClientId"]! },
                    { "client_secret", _config["GitHub:ClientSecret"]! },
                    { "code", code }
                };

            //  get github access token
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, "https://github.com/login/oauth/access_token")
            {
                Content = new FormUrlEncodedContent(tokenRequest)
            };
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await client.SendAsync(requestMessage);
            var tokenResult = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();

            if (tokenResult == null || !tokenResult.TryGetValue("access_token", out var tokenValue))
            {
                return BadRequest("Failed to get response data from GitHub.");
            }

            var githubAccessToken = tokenValue?.ToString();
            if (string.IsNullOrEmpty(githubAccessToken))
                return BadRequest("Failed to extract GitHub token.");

            // 2. Fetch User Profile Data from GitHub

            var userRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
            userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", githubAccessToken);
            userRequest.Headers.UserAgent.ParseAdd("GitHubAuthApi"); // Required by GitHub API

            var userResponse = await client.SendAsync(userRequest);
            if (!userResponse.IsSuccessStatusCode)
            {
                return BadRequest("Failed to fetch user profile from GitHub API.");
            }

            using var jsonDocument = JsonDocument.Parse(await userResponse.Content.ReadAsStringAsync());

            // Ensure "login" property exists before extracting
            if (!jsonDocument.RootElement.TryGetProperty("login", out var loginProperty))
            {
                return BadRequest("Could not find user login identifier in profile data.");
            }
            var username = loginProperty.GetString();

            // 3. Generate your local JWT App Token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]!);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.Name, username!),
            new Claim("GitHubUsername", username!)
        }),
                Expires = DateTime.UtcNow.AddHours(2),
                Issuer = _config["Jwt:Issuer"],
                Audience = _config["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(new { Token = tokenHandler.WriteToken(token) });
        }

    }
}
