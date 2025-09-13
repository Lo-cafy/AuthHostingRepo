using Grpc.Core;
using Grpc.Core.Interceptors;

namespace AuthService.Grpc.Interceptors
{
    public class RateLimitInterceptor : Interceptor
    {
        public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
            TRequest request,
            ServerCallContext context,
            UnaryServerMethod<TRequest, TResponse> continuation)
        {
            // Add rate limiting logic 
            return await continuation(request, context);
        }
    }
}