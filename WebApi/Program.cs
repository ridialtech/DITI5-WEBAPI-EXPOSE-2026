using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json.Serialization;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Services;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

// =============================
//  DATABASE CONFIGURATION
// =============================

var connectionString = configuration.GetConnectionString("DbCahierTexteContext");

// DataContext avec configuration locale (OnConfiguring)
builder.Services.AddDbContext<DataContext>(options => options.UseNpgsql(connectionString));

// ApplicationDbContext utilise la M�ME connection string
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseNpgsql(connectionString));

// =============================
//  IDENTITY CONFIGURATION
// =============================

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// =============================
//  JWT AUTHENTICATION
// =============================

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "MultiScheme";
    options.DefaultChallengeScheme    = "MultiScheme";

})
.AddJwtBearer( "LocalJwt", options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.Zero,
        ValidAudience = configuration["JWT:ValidAudience"],
        ValidIssuer = configuration["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(configuration["JWT:Secret"]))
    };

});


// ── Schéma 2 : Keycloak ──────────────────────────────────────
.AddJwtBearer("Keycloak", options =>
{
    options.Authority            = configuration["Keycloak:Authority"];
    
    options.Audience             = configuration["Keycloak:Audience"];
    options.RequireHttpsMetadata = false; 
    options.SaveToken            = true;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer   = true,
        ValidIssuer      = configuration["Keycloak:Authority"],
        ValidateAudience = true,
        ValidateLifetime = true,
        ClockSkew        = TimeSpan.Zero
    };

    // Mapper les rôles Keycloak → ClaimTypes.Role
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            var identity    = context.Principal?.Identity as ClaimsIdentity;
            var realmAccess = context.Principal?.FindFirst("realm_access")?.Value;

            if (realmAccess is not null)
            {
                var roles = JsonDocument.Parse(realmAccess)
                    .RootElement
                    .GetProperty("roles")
                    .EnumerateArray();

                foreach (var role in roles)
                    identity?.AddClaim(new Claim(ClaimTypes.Role, role.GetString()!));
            }
            return Task.CompletedTask;
        }
    };
})
// ── Schéma combiné : essaie LocalJwt d'abord, puis Keycloak ──
.AddPolicyScheme("MultiScheme", "LocalJwt OR Keycloak", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

        if (authHeader?.StartsWith("Bearer ") == true)
        {
            var token   = authHeader.Substring("Bearer ".Length).Trim();
            var handler = new JwtSecurityTokenHandler();

            if (handler.CanReadToken(token))
            {
                var jwt    = handler.ReadJwtToken(token);
                var issuer = jwt.Issuer;

                // Si l'issuer correspond à Keycloak → schéma Keycloak
                if (issuer.Contains(configuration["Keycloak:Authority"]!))
                    return "Keycloak";
            }
        }

        // Par défaut → ton JWT local
        return "LocalJwt";
    };
});

builder.Services.AddAuthorization(options =>
{
    // Politique qui accepte l'un ou l'autre
    options.AddPolicy("AnyScheme", policy =>
        policy.AddAuthenticationSchemes("LocalJwt", "Keycloak")
              .RequireAuthenticatedUser());

    // Politique réservée aux admins Keycloak
    options.AddPolicy("KeycloakAdmin", policy =>
        policy.AddAuthenticationSchemes("Keycloak")
              .RequireRole("admin"));
});

// =============================
//  CONTROLLERS + JSON OPTIONS
// =============================

builder.Services.AddControllers()
    .AddJsonOptions(x =>
    {
        x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        x.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });

// =============================
//  CORS, AUTO MAPPER & SERVICES
// =============================

builder.Services.AddCors();
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
builder.Services.AddScoped<IUserService, UserService>();

// =============================
// SWAGGER / API DOCUMENTATION
// =============================

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// =============================
//  BUILD APPLICATION
// =============================

var app = builder.Build();

// =============================
// MIDDLEWARE PIPELINE
// =============================

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(x => x
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader());

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<ErrorHandlerMiddleware>();

app.MapControllers();

// =============================
//  RUN APPLICATION
// =============================

app.Run();