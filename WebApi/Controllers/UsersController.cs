namespace WebApi.Controllers;

using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using WebApi.Models.Users;
using WebApi.Services;
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;
    private IMapper _mapper;
    public UsersController(IUserService userService, IMapper mapper)
    {
        _userService = userService;
        _mapper = mapper;
    }
    [HttpGet]
    public IActionResult GetAll()
    {
        var users = _userService.GetAll();
        return Ok(users);
    }
    [HttpGet("{id}")]
    public IActionResult GetById(int id)
    {
        var user = _userService.GetById(id);
        return Ok(user);
    }
    [HttpPost]
    public IActionResult Create(CreateRequest model)
    {
        _userService.Create(model);
        return Ok(new { message = "User created" });
    }
    [HttpPut]
    public IActionResult Update(UpdateRequest model)
    {
        _userService.Update(model);
        return Ok(new { message = "User updated" });
    }
    [HttpDelete("{id}")]
    public IActionResult Delete(int id)
    {
        _userService.Delete(id);
        return Ok(new { message = "User deleted" });
    }

     [HttpGet]
    public IActionResult Get()
    {
        // Fonctionne pour les deux schémas
        var username = User.FindFirst("preferred_username")?.Value   // Keycloak
                    ?? User.FindFirst(ClaimTypes.Name)?.Value;       // Local JWT

        return Ok(new { username });
    }
}
