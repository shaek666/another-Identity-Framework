    using System.Net;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Identity;

    var builder = WebApplication.CreateBuilder(args);

    // builder.Services
    //     .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    //     .AddCookie(options =>
    //     {
    //         options.Cookie.Name = "Friday";

    //         options.Events.OnRedirectToLogin = context =>
    //         {
    //             context.Response.StatusCode = 401;
    //             return Task.CompletedTask;
    //         };
    //     });


    // builder.Services.AddAuthorization();


    var app = builder.Build();

    app.Use(async (context, next) =>
    {
        if (context.Request.Path.StartsWithSegments("/login"))
        {
            await next();
            return;
        }

        var authCookie = context.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith(("friday")));

        if (authCookie == null || authCookie.Length <= 0)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized: No authentication cookie found.");
            return;
        }

        var payload = authCookie.Split("=").Last();
        var parts = payload.Split(":");
        var key = parts[0];
        var value = parts[1];

        var claims = new List<Claim>
        {
            new(key, value)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(claimsIdentity);
        await next();
    });

    // app.UseAuthentication();
    // app.UseAuthorization();

    // app.MapGet("/cookie-authorized", (HttpContext context) =>
    // {
    //     return Results.Ok("You're authenticated by Cookie"); // This ain't an authenticated route, like 
    // }).RequireAuthorization();

    // app.MapGet("/login", async (string userName, string password, HttpContext context) =>
    // {
    //     if (userName != "jackiechan" && password != "password") return Results.Unauthorized();

    //     //Generating secrets if userName == jackiechan and password is password, assuming these will always be the username and password as we are hardcoding it.
    //     var claims = new List<Claim>
    //     {
    //         new("username", userName),
    //         new("movie", "rush-hour-3")
    //     };
    //     var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    //     var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

    //     await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);
    //     return Results.Ok();
    // });

    // app.MapGet("/logout", (string userName, string password, HttpContext context) =>
    // {
    //     if (userName != "jackiechan" && password != "password") return Results.Unauthorized();

    //     var secret = $"username:{userName}";
    //     context.Response.Headers["set-cookie"] = $"sunday= {secret}";
    //     return Results.Ok();
    // });

    app.MapGet("/cookie-authorized", (HttpContext context) =>
    {
        var value = context.User.FindFirst("username");
        return Results.Ok(value?.Value);
    });

    app.MapGet("/login", async (string userName, string password, HttpContext context) =>
    {
        if (userName != "jackiechan" || password != "password") return Results.Unauthorized();
        var secret = $"username:{userName}";
        context.Response.Headers["set-cookie"] = $"friday={secret}";
        return Results.Ok("Login successful! Cookie has been set.");
    });

    app.Run();

    public class AuthFactory
    {
        public static async Task SignInAsync(string scheme)
        {
            if (scheme == "cookie") await new CookieAuthService().SignInAsync();
            if (scheme == "bearer") await new BearerAuthService().SignInAsync();
        }
    }

    public interface IAuthService
    {
        public Task SignInAsync();
    }

    public class CookieAuthService : IAuthService
    {
        public Task SignInAsync()
        {
            Console.WriteLine("Executing Strategy: Sign in with Cookie");
            return Task.CompletedTask;
        }
    }

    public class BearerAuthService : IAuthService
    {
        public Task SignInAsync()
        {
            Console.WriteLine("Executing Strategy: Sign in with Bearer Token");
            return Task.CompletedTask;
        }
    }
