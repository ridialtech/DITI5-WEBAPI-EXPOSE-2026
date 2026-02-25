using System.Text.Json.Serialization;
using System.ComponentModel.DataAnnotations;

namespace WebApi.Entities;

public class User
{
    [Required]
    public int Id { get; set; }
    [Required]

    public required string Title { get; set; }
    [Required]
    [MaxLength(50)]
    public required string FirstName { get; set; }
    [Required]
    [MaxLength(50)]
    public required string LastName { get; set; }
    [Required]
    [MaxLength(100)]
    public required string Email { get; set; }
    [Required]
    public Role Role { get; set; }

    [JsonIgnore]
    public string? PasswordHash { get; set; }
}

