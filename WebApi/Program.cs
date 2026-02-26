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

// ApplicationDbContext utilise la MÊME connection string
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
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
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

builder.Services.AddAuthorization();

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
// Ajout Grpc
// =============================
builder.Services.AddControllers();
builder.Services.AddGrpc();
builder.Services.AddDbContext<DataContext>();



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
// Ajout Grpc services
// =============================

// =============================
// MIDDLEWARE PIPELINE
// =============================
app.UseRouting();
app.UseAuthorization();

app.MapControllers();
app.MapGrpcService<WebApi.GrpcServices.UserGrpcService>();



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