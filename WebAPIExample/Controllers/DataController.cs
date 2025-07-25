using AuthLibrary;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPIExample.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class DataController : ControllerBase
    {
        [HttpPost("execute")]
        public IActionResult ExecuteSql(string dsn, string sql, [FromBody] Dictionary<string, object> parameters)
        {
            var result = AuthService.ExecuteSql(dsn, sql, parameters);
            return Ok(result);
        }
    }
}
