using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class AuthenticationService
{
  private readonly IConfiguration _configuration;

  private readonly string _issuer;
  private readonly string _audience;
  private readonly string _key;

  public AuthenticationService(IConfiguration configuration)
  {
    _configuration = configuration;

    _issuer = _configuration["Jwt:Issuer"] ?? "";
    _audience = _configuration["Jwt:Audience"] ?? "";
    _key = _configuration["Jwt:Key"] ?? "";

    if (string.IsNullOrEmpty(_issuer) || string.IsNullOrEmpty(_audience) || string.IsNullOrEmpty(_key))
    {
      throw new Exception("Jwt:Issuer, Jwt:Audience and Jwt:Key must be configured");
    }
  }

  public string GenerateToken(User user)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(_key);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
      Issuer = _issuer,
      Audience = _audience,
      Subject = new ClaimsIdentity(new[]
      {
        new Claim("Id", Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.Name, user.Username)
      }),
      Expires = DateTime.UtcNow.AddDays(7),
      SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
  }

  public bool ValidateToken(string token)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(_key);
    try
    {
      tokenHandler.ValidateToken(token, new TokenValidationParameters
      {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidIssuer = _issuer,
        ValidAudience = _audience,
      }, out SecurityToken validatedToken);
    }
    catch
    {
      return false;
    }

    return true;
  }
}
