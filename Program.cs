using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
// using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql("Host=localhost;Port=5432;Database=identity_db;Username=postgres;Password=password");
});

builder.Services
    .AddIdentity<IdentityUser, IdentityRole>(options =>
    {
        options.Password.RequireDigit = false;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;
        options.Password.RequiredLength = 1;
        options.Password.RequiredUniqueChars = 0;

    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

var key = "a-very-long-and-secure-secret-key-at-least-32-chars"u8.ToArray();

builder.Services.AddAuthentication()
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "another-Identity-Framework",
            ValidAudience = "another-Identity-Framework",
            IssuerSigningKey = new SymmetricSecurityKey("a-very-long-and-secure-secret-key-at-least-32-chars"u8.ToArray())
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("admin-policy", policy =>
    {
        policy.RequireClaim("org", "ait");
        policy.RequireRole("admin");
        policy.RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (
    string email, 
    string password, 
    UserManager<IdentityUser> userManager) =>
{
    var user = new IdentityUser
    {
        UserName = email,
        Email = email
    };
    var result = await userManager.CreateAsync(user, password);

    if(!result.Succeeded) return Results.BadRequest("User creation failed");

    return Results.Ok("User Created");
});

app.MapGet("/login", async (
    string email, 
    string password, 
    UserManager<IdentityUser> userManager) =>
{
    if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)) return Results.Unauthorized();

    var user = await userManager.FindByEmailAsync(email);
    if(user is null) return Results.Unauthorized();

    var isPasswordValid = await userManager.CheckPasswordAsync(user, password);
    if(!isPasswordValid) return Results.Unauthorized();

    var organization = email switch
    {
        var e when e.EndsWith("@ait.com") => "ait",
        var e when e.EndsWith("@optimizely.com") => "optimizely",
        var e when e.EndsWith("@fieldnation.com") => "fieldnation",
    };

    var role = email switch
    {
        var e when e.EndsWith("rick@ait.com") => "admin",
        _ => "user"
    };

    var tokenDescriptor = new SecurityTokenDescriptor
    {
       Subject = new ClaimsIdentity([
           new Claim(JwtRegisteredClaimNames.Email, email),
           new Claim("org", organization),
           new Claim(ClaimTypes.Role, role),
       ]),
       Expires = DateTime.UtcNow.AddMinutes(30),
       Issuer = "another-Identity-Framework",
       Audience = "another-Identity-Framework",
       SigningCredentials = new SigningCredentials(
           new SymmetricSecurityKey(key),
           SecurityAlgorithms.HmacSha256Signature
       )
    };
    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = tokenHandler.WriteToken(token);
    return Results.Ok(new { token = jwtToken });
});

app.MapGet("/ait-resources", (HttpContext context) =>
{
    return Results.Ok("You accessed AIT resources");
}).RequireAuthorization(policy =>
{
    policy.RequireClaim("org", "ait");
    policy.RequireAuthenticatedUser();
});

app.MapGet("/ait-admin-resources", (HttpContext context) =>
{
    return Results.Ok("You accessed AIT admin resources");
}).RequireAuthorization("admin-policy");



app.MapGet("/optimizely-resources", () =>
{
    return Results.Ok("You accessed Optimizely resources");
}).RequireAuthorization(policy =>
{
    policy.RequireClaim("org", "optimizely");
    policy.RequireAuthenticatedUser();
});;

app.MapGet("/fieldnation-resources", () =>
{
    return Results.Ok("You accessed Filed Nation resources");
}).RequireAuthorization(policy =>
{
    policy.RequireClaim("org", "fieldnation");
    policy.RequireAuthenticatedUser();
});;

app.Run();
