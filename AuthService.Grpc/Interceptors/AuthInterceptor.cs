using Grpc.Core;
using Grpc.Core.Interceptors;

namespace AuthService.Grpc.Interceptors
{
    public class AuthInterceptor : Interceptor
    {
        public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
            TRequest request,
            ServerCallContext context,
            UnaryServerMethod<TRequest, TResponse> continuation)
        {
            // Add authentication logic
            return await continuation(request, context);
        }
    }
}