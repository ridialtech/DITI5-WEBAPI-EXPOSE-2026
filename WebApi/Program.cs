using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
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
    options.DefaultChallengeScheme = "MultiScheme";

})

.AddPolicyScheme("MultiScheme", "MultiScheme", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

        if (authHeader != null && authHeader.StartsWith("Bearer "))
        {
            var token = authHeader.Substring("Bearer ".Length).Trim();

            // Si token commence par ton secret JWT local → LocalJwt
            if (token.Length > 20 && token.Contains("."))
                return "LocalJwt";
        }

        return "keycloak";
    };
})
.AddJwtBearer("LocalJwt", options =>
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

})

// ================= Keycloak JWT =================
.AddJwtBearer("keycloak", options =>
 {
     options.Authority = configuration["Keycloak:Authority"];
     options.RequireHttpsMetadata = false;
     options.SaveToken = true;

     options.TokenValidationParameters = new TokenValidationParameters
     {
         ValidateIssuer = true,
         ValidateAudience = true,
         ValidateLifetime = true,
         ClockSkew = TimeSpan.Zero,

         ValidAudience = configuration["Keycloak:Audience"]
     
 };

     options.Events = new JwtBearerEvents
     {
         OnTokenValidated = context =>
         {
             var identity = context.Principal?.Identity as ClaimsIdentity;

             var realmAccess = context.Principal?
                 .FindFirst("realm_access")?
                 .Value;

             if (!string.IsNullOrEmpty(realmAccess))
             {
                 try
                 {
                     var roles = JsonDocument.Parse(realmAccess)
                         .RootElement
                         .GetProperty("roles")
                         .EnumerateArray();

                     foreach (var role in roles)
                     {
                         identity?.AddClaim(
                             new Claim(ClaimTypes.Role, role.GetString() ?? "")
                         );
                     }
                 }
                 catch { }
             }

             return Task.CompletedTask;
         }
     };
 });


object AddJwtBearer(string v, Action<object> value)
{
    throw new NotImplementedException();
}

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