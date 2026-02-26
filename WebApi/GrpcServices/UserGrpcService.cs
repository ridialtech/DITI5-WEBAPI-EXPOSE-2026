using Grpc.Core;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Services;

namespace WebApi.GrpcServices
{
    public class UserGrpcService : UserService.UserServiceBase
    {
        private readonly DataContext _context;

        public UserGrpcService(DataContext context)
        {
            _context = context;
        }

        public override async Task<UserResponse> GetUser(UserRequest request, ServerCallContext context)
        {
            var user = await _context.Users.FindAsync(request.UserId);

            if (user == null)
                throw new RpcException(new Status(StatusCode.NotFound, "User not found"));

            return new UserResponse
            {
                UserId = user.Id,
                Title = user.Title ?? "",
                FirstName = user.FirstName ?? "",
                LastName = user.LastName ?? "",
                Email = user.Email ?? "",
                Role = user.Role.ToString()
            };
        }
    }
}