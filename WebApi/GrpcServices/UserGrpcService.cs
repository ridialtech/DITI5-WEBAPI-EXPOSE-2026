using Grpc.Core;
using WebApi.Services;

namespace WebApi.GrpcServices
{
    public class UserGrpcService : UserGrpc.UserGrpcBase
    {
        private readonly IUserService _userService;

        public UserGrpcService(IUserService userService)
        {
            _userService = userService;
        }

        public override Task<UserResponse> GetUser(UserRequest request, ServerCallContext context)
        {
            try
            {
                var user = _userService.GetById(request.UserId);
                return Task.FromResult(new UserResponse
                {
                    UserId = user.Id,
                    Title = user.Title ?? "",
                    FirstName = user.FirstName ?? "",
                    LastName = user.LastName ?? "",
                    Email = user.Email ?? "",
                    Role = user.Role.ToString()
                });
            }
            catch (KeyNotFoundException)
            {
                throw new RpcException(new Status(StatusCode.NotFound, "User not found"));
            }
        }
    }
}