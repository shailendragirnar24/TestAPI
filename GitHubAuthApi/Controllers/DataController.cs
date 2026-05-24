using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace GitHubAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DataController : ControllerBase
    {
        // Accessible by anyone with a valid JWT token
        [Authorize]
        [HttpGet("secure-data")]
        public IActionResult GetSecureData()
        {
            return Ok(new { Message = "This is secured. You are authenticated via GitHub!" });
        }

        // Accessible ONLY if your GitHub username matches the policy configuration
        [Authorize(Policy = "AdminOnly")]
        [HttpGet("admin-data")]
        public IActionResult GetAdminData()
        {
            return Ok(new { Message = "Welcome Admin! You have passed GitHub authorization checks." });
        }
    }
}
