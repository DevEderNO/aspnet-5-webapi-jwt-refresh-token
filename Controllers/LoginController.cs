using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RefreshTokenAuth.Models;
using RefreshTokenAuth.Repositories;
using RefreshTokenAuth.Services;

namespace RefreshTokenAuth.Controllers
{
  [ApiController]
  public class LoginController : ControllerBase
  {
    [HttpPost]
    [Route("login")]
    public ActionResult<dynamic> Authenticate([FromBody] User model)
    {
      var user = UserRepository.Get(model.Username, model.Password);
      if (user == null)
        return NotFound(new { message = "Invalid username or password" });
      var token = TokenService.GenerateToken(user);
      var refreshToken = TokenService.GetRefreshToken(token);
      TokenService.SaveRefreshToken(user.Username, refreshToken);
      user.Password = "";
      return new
      {
        user,
        token,
        refreshToken
      };
    }

    public partial class RefreshTO
    {
      public string Token { get; set; }
      public string RefreshToken { get; set; }
    }

    [HttpPost]
    [Route("refresh")]
    public IActionResult Refresh([FromBody] RefreshTO refreshTO)
    {
      var principal = TokenService.GetPrincipalFromExpiredToken(refreshTO.Token);
      var username = principal.Identity.Name;
      var savedRefreshToken = TokenService.GetRefreshToken(username);
      if (savedRefreshToken != refreshTO.RefreshToken)
        throw new SecurityTokenException("Invalid refresh token");

      var newJwtToken = TokenService.GenerateToken(principal.Claims);
      var newRefreshToken = TokenService.GenerateRefrashToken();
      TokenService.DeleteRefreshToken(username, savedRefreshToken);
      TokenService.SaveRefreshToken(username, newRefreshToken);
      return new ObjectResult(new
      {
        token = newJwtToken,
        refreshToken = newRefreshToken
      });
    }
  }
}
