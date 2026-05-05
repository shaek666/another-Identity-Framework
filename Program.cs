using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

var key = "secret-key-123456789101112akakakakcjncnckclcnccnaocnixnicnzincizxj";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("Bearer")
    .AddCookie()
    .AddJwtBearer(options =>
    {
       options.TokenValidationParameters = new TokenValidationParameters
       {
           ValidateIssuer = false,
           ValidateAudience = false,
           ValidateLifetime = true,
           ValidateIssuerSigningKey = true,
           IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
       };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login-with-cookie", async (string userName, string password, HttpContext context) =>
{
   var claims = new List<Claim>
   {
       new("username", userName)
   };
//    if(userName != "jackiechan" || password != "password") return Results.Unauthorized();

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme))
    );

    Results.Ok();
});

app.MapGet("/secure", (HttpContext context) =>
{
   return Results.Ok("Secured endpoint"); 
}).RequireAuthorization(/*policy =>
{
    policy.AddAuthenticationSchemes("Bearer");
    policy.RequireAuthenticatedUser();
}*/ //Explicitly declare the default authentication type here or via params of AddAuthentication(/*here*/) [It's there for now]
policy =>
{
    policy.AddAuthenticationSchemes("Bearer");
    policy.AddAuthenticationSchemes("Cookies");
    policy.RequireAuthenticatedUser();
}); //...and when both system are asked, 2 (both jwt and cookie) claims principal are created, Authentication Types Federation and Cookies! try debugger to verify.

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