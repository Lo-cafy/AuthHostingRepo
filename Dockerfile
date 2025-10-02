# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files and restore dependencies
# (Using your project structure for caching)
COPY ["AuthService.Api/AuthService.Api.csproj", "AuthService.Api/"]
COPY ["AuthService.Application/AuthService.Application.csproj", "AuthService.Application/"]
COPY ["AuthService.Domain/AuthService.Domain.csproj", "AuthService.Domain/"]
COPY ["AuthService.Infrastructure/AuthService.Infrastructure.csproj", "AuthService.Infrastructure/"]
COPY ["AuthService.Grpc/AuthService.Grpc.csproj", "AuthService.Grpc/"]
COPY ["AuthService.Shared/AuthService.Shared.csproj", "AuthService.Shared/"]
COPY ["Locafy-AuthService.sln", "."]
RUN dotnet restore "Locafy-AuthService.sln"

# Copy the rest of the source code
COPY . .

# Publish the application
WORKDIR "/src/AuthService.Api"
RUN dotnet publish "AuthService.Api.csproj" -c Release -o /app/publish

# Stage 2: Create the final, smaller image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# Expose the port Render expects
EXPOSE 10000

# Set the entry point for the application
ENTRYPOINT ["dotnet", "AuthService.Api.dll"]
