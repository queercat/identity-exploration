using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[AllowAnonymous]
[Route("security")]
public class AuthController : Controller
{
  private readonly AuthenticationService _authenticationService;

  public AuthController(AuthenticationService authenticationService)
  {
    _authenticationService = authenticationService;
  }

  [HttpPost("login")]
  public IActionResult Login([FromBody] User user)
  {
    if (user.Username == "admin" && user.Password == "admin")
    {
      var token = _authenticationService.GenerateToken(user);

      // set the token in a http-only cookie
      Response.Cookies.Append("token", token, new CookieOptions
      {
        HttpOnly = true
      });

      // Set user as authenticated.
      HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(new[]
      {
        new Claim(ClaimTypes.Name, user.Username)
      }, "user"));

      // Set identity as authenticated.
      HttpContext.User.Identity.IsAuthenticated = true;

      return RedirectToAction("Secret");
    }

    return Unauthorized();
  }

  // return a basic login page.
  [HttpGet("login")]
  public IActionResult Login()
  {
    // Get the token from the cookie.
    var user = HttpContext.User;

    if (user.Identity.IsAuthenticated)
    {
      return RedirectToAction("Secret");
    }

    return View();
  }

  [HttpGet("logout")]
  public IActionResult Logout()
  {
    // Remove the token from the cookie.
    Response.Cookies.Delete("token");

    return RedirectToAction("Login");
  }

  [HttpGet("secret")]
  [Authorize]
  public IActionResult Secret()
  {
    var user = HttpContext.User;

    if (user == null)
    {
      return Unauthorized();
    }

    return Ok($"This is a secret message. ${Request.Cookies["token"]}");
  }
}
