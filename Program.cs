using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

var key = "secret-key-123456789101112akakakakcjncnckclcnccnaocnixnicnzincizxj";

app.MapGet("/secure", (HttpContext context) =>
{
    var authHeader = context.Request.Headers.Authorization.ToString();
    if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ")) return Results.Unauthorized();

    var token = authHeader.Replace("Bearer ", "");
    var handler = new JwtSecurityTokenHandler();
    var parameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
    };

    var principal = handler.ValidateToken(token, parameters, out var validatedToken);
    if (principal == null) return Results.Unauthorized();

    var userName = principal.FindFirst(ClaimTypes.Name).Value;
    var role = principal.FindFirst(ClaimTypes.Role).Value;

    return Results.Ok(new
    {
        message = "Valid token",
        userName,
        role
    });
});

app.MapGet("/login-with-jwt", (string userName, string password) =>
{
    if (userName != "jackiechan" || password != "password") return Results.Unauthorized();
    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, userName),
        new(ClaimTypes.Role, "admin")
    };

    var tokenDescriptor = new SecurityTokenDescriptor()
    {
        Subject =  new ClaimsIdentity(claims),
        Expires =  DateTime.UtcNow.AddMinutes(30),
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
            SecurityAlgorithms.HmacSha256Signature
        )
    };

    var handler = new JwtSecurityTokenHandler();
    var token = handler.CreateToken(tokenDescriptor);
    var jwt = handler.WriteToken(token);

    return Results.Ok(new { token = jwt });
});

app.Run();