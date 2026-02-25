namespace WebApi.Helpers;
using Microsoft.EntityFrameworkCore;
using WebApi.Entities;

public class DataContext : DbContext
{
    //protected readonly IConfiguration Configuration;
    //public DataContext(IConfiguration configuration)
    //{
    //    Configuration = configuration;
    //}
    //protected override void OnConfiguring(DbContextOptionsBuilder options)
    //{
    //    // in memory database used for simplicity, change to a real db production applications
    //    //options.UseInMemoryDatabase("TestDb");
    //    options.UseNpgsql(Configuration.GetConnectionString("DbCahierTexteContext"));
    //}
    public DataContext(DbContextOptions<DataContext> options)
        : base(options)
    {
    }
    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configuration de l'entité User
        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("users");

            entity.HasIndex(e => e.Email).IsUnique();

            entity.Property(e => e.Role)
                .HasConversion<string>();
        });
    }
}
