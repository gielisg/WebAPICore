using AuthLibrary;
using Microsoft.AspNetCore.Mvc;

namespace WebAPIExample.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private const string SecretKey = "your_super_secret_key";

        [HttpPost("register")]
        public IActionResult Register(string username, string password)
        {
            var (hashedPassword, securityStamp) = AuthService.HashPassword(password);
            return Ok(new { hashedPassword, securityStamp });
        }

        [HttpPost("login")]
        public IActionResult Login(string username, string password)
        {
            // Retrieve the hashed password and security stamp from your database
            var hashedPassword = "retrieved_hashed_password";
            var securityStamp = "retrieved_security_stamp";

            if (AuthService.VerifyPassword(hashedPassword, password, securityStamp))
            {
                var refreshToken = AuthService.GenerateJwtToken(username, "User", "your_dsn", "refresh", SecretKey, 60 * 24 * 7);
                return Ok(new { refreshToken });
            }

            return Unauthorized();
        }

        [HttpPost("refresh")]
        public IActionResult Refresh(string refreshToken)
        {
            try
            {
                var principal = AuthService.GetPrincipalFromExpiredToken(refreshToken, SecretKey);

                if (principal?.Identity?.Name is null)
                {
                    return Unauthorized();
                }

                var username = principal.Identity.Name;
                var role = principal.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
                var dsn = principal.FindFirst("dsn")?.Value;

                if (username is null || role is null || dsn is null)
                {
                    return Unauthorized();
                }

                var accessToken = AuthService.GenerateJwtToken(username, role, dsn, "access", SecretKey, 15);
                return Ok(new { accessToken });
            }
            catch
            {
                return Unauthorized();
            }
        }

        [HttpGet("anonymous")]
        public IActionResult GetAnonymousToken()
        {
            var anonymousToken = AuthService.GenerateJwtToken("anonymous", "Anonymous", "", "anonymous", SecretKey, 60);
            return Ok(new { anonymousToken });
        }

        [HttpGet("apikey")]
        public IActionResult GetApiKey()
        {
            var apiKey = AuthService.GenerateJwtToken("api_key_user", "API", "", "apikey", SecretKey, 60 * 24 * 365);
            return Ok(new { apiKey });
        }
    }
}
