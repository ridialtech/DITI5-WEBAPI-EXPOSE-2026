namespace WebApi.Models.Users;

using System.ComponentModel.DataAnnotations;
using WebApi.Entities;
public class CreateRequest
{
    [Required]
    public required string Title { get; set; }
    [Required]
    public required string FirstName { get; set; }
    [Required]
    public required string LastName { get; set; }
    [Required]
    [EnumDataType(typeof(Role))]
    public required string Role { get; set; }
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    [Required]
    [MinLength(6)]
    public required string Password { get; set; }
    [Required]
    [Compare("Password")]
    public required string ConfirmPassword { get; set; }
}