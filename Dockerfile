# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution and project files
COPY ["AuthService.sln", "."]
COPY ["AuthService.Application/", "AuthService.Application/"]
COPY ["AuthService.Domain/", "AuthService.Domain/"]
COPY ["AuthService.Grpc/", "AuthService.Grpc/"]
COPY ["AuthService.Infrastructure/", "AuthService.Infrastructure/"]
COPY ["AuthService.Shared/", "AuthService.Shared/"]
COPY ["AuthService.Grpc.Client/", "AuthService.Grpc.Client/"]
COPY ["AuthService/", "AuthService/"]

# Restore dependencies
RUN dotnet restore "AuthService.sln"

# Publish the API project
WORKDIR "/src/AuthService"
RUN dotnet publish "AuthService.Api.csproj" -c Release -o /app/publish

# Stage 2: Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Security: create non-root user
RUN adduser --disabled-password --gecos "" appuser
USER appuser

# Copy published app
COPY --from=build /app/publish .

# Expose port (Railway uses dynamic PORT env)
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

# Entry point
ENTRYPOINT ["dotnet", "AuthService.Api.dll"]