using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Entities;
using WebApi.Helpers;
namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        public AuthenticateController(  
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration,
        HttpClient httpClient)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _httpClient = httpClient;
        }
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await
            _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await
                _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,
                    Guid.NewGuid().ToString()),
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var token = CreateToken(authClaims);
                var refreshToken = GenerateRefreshToken();
                _ =
                int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out
                int refreshTokenValidityInDays);
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(refreshTokenValidityInDays);
                await _userManager.UpdateAsync(user);
                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

    // ─────────────────────────────────────────────────────────
    // NOUVEAU : Login Keycloak → Keycloak génère le JWT
    // ─────────────────────────────────────────────────────────
    [HttpPost("keycloak-login")]
    public async Task<IActionResult> KeycloakLogin([FromBody] LoginModel model)
    {
        var keycloakUrl = _configuration["Keycloak:Authority"];
        var clientId    = _configuration["Keycloak:ClientId"];
        var secret      = _configuration["Keycloak:ClientSecret"];

        // Appel direct au Token Endpoint de Keycloak
        var formData = new Dictionary<string, string>
        {
            ["grant_type"]    = "password",
            ["client_id"]     = clientId!,
            ["client_secret"] = secret!,
            ["username"]      = model.Username,
            ["password"]      = model.Password,
            ["scope"]         = "openid profile email"
        };

        var response = await _httpClient.PostAsync(
            $"{keycloakUrl}/protocol/openid-connect/token",
            new FormUrlEncodedContent(formData));

        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync();
            return Unauthorized(new { message = "Keycloak authentication failed", detail = error });
        }

        var result = await response.Content.ReadFromJsonAsync<KeycloakTokenResponse>();

        return Ok(new
        {
            token = result.AccessToken ?? "",
            refresh_token = result.RefreshToken ?? "",
            expiration = DateTime.UtcNow.AddSeconds(result.ExpiresIn),
            source = "keycloak"
        });
    }


    // ─────────────────────────────────────────────────────────
    // NOUVEAU : Refresh Token Keycloak
    // ─────────────────────────────────────────────────────────
    [HttpPost("keycloak-refresh")]
    public async Task<IActionResult> KeycloakRefresh([FromBody] RefreshTokenModel model)
    {
        var keycloakUrl = _configuration["Keycloak:Authority"];
        var clientId    = _configuration["Keycloak:ClientId"];
        var secret      = _configuration["Keycloak:ClientSecret"];

        var formData = new Dictionary<string, string>
        {
            ["grant_type"]    = "refresh_token",
            ["client_id"]     = clientId!,
            ["client_secret"] = secret!,
            ["refresh_token"] = model.RefreshToken
        };

        var response = await _httpClient.PostAsync(
            $"{keycloakUrl}/protocol/openid-connect/token",
            new FormUrlEncodedContent(formData));

        if (!response.IsSuccessStatusCode)
            return Unauthorized(new { message = "Refresh token invalide ou expiré" });

        var result = await response.Content.ReadFromJsonAsync<KeycloakTokenResponse>();
        return Ok(result);
    }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await
            _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "User already exists!"
                });
            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "User creation failed! Please check user details and try again."
                });
            return Ok(new Response
            {
                Status = "Success",
                Message =
            "User created successfully!"
            });
        }
        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody]
RegisterModel model)
        {
            var userExists = await
            _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return
                StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "User already exists!"
                });
            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user,
            model.Password);
            if (!result.Succeeded)
                return
                StatusCode(StatusCodes.Status500InternalServerError, new Response
                {
                    Status = "Error",
                    Message = "User creation failed! Please check user details and try again."
                });
            if (!await _roleManager.RoleExistsAsync(Role.Admin.ToString()))
                await _roleManager.CreateAsync(new IdentityRole(Role.Admin.ToString()));
            if (!await _roleManager.RoleExistsAsync(Role.User.ToString()))
                await _roleManager.CreateAsync(new IdentityRole(Role.User.ToString()));
            if (await _roleManager.RoleExistsAsync(Role.Admin.ToString()))
            {
                await _userManager.AddToRoleAsync(user, Role.Admin.ToString());
            }
            if (await _roleManager.RoleExistsAsync(Role.User.ToString()))
            {
                await _userManager.AddToRoleAsync(user, Role.User.ToString());
            }
            return Ok(new Response
            {
                Status = "Success",
                Message = "User created successfully!"
            });
        }
        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel
        tokenModel)
        {
            if (tokenModel is null)
            {
                return BadRequest("Invalid client request");
            }
            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;
            var principal =
            GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return BadRequest("Invalid access token or token");
            }
#pragma warning disable CS8600 // Converting null literal or possible null value to non - nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            string username = principal.Identity.Name;
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non - nullable type.
            var user = await _userManager.FindByNameAsync(username);
            if (user == null || user.RefreshToken != refreshToken ||
            user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return BadRequest("Invalid access token or refresh token");
            }
            var newAccessToken =
            CreateToken(principal.Claims.ToList());
            var newRefreshToken = GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);
            return new ObjectResult(new
            {
                accessToken = new
            JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken
            });
        }
        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return BadRequest("Invalid user name");


            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);
            return NoContent();
        }
        [Authorize]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }
            return NoContent();
        }
        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new
        SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
            return token;
        }
        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal?
        GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new
            TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new
            SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            return principal;
        }
    }
}