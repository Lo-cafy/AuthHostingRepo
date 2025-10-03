# Stage 1: Build the application
# This stage compiles your .NET application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy all .csproj files and the .sln file first for better caching
# Correcting all file paths and the solution file name based on your GitHub repo.
COPY ["AuthService.Api.csproj", "AuthService.Api/"]
COPY ["AuthService.Application/AuthService.Application.csproj", "AuthService.Application/"]
COPY ["AuthService.Domain/AuthService.Domain.csproj", "AuthService.Domain/"]
COPY ["AuthService.Infrastructure/AuthService.Infrastructure.csproj", "AuthService.Infrastructure/"]
COPY ["AuthService.Grpc/AuthService.Grpc.csproj", "AuthService.Grpc/"]
COPY ["AuthService.Shared/AuthService.Shared.csproj", "AuthService.Shared/"]
COPY ["AuthService.sln", "."]
RUN dotnet restore "AuthService.sln"

# Copy the rest of the source code
COPY . .

# Publish the main API project
# Changing the working directory to the correct location before publishing
WORKDIR "/src/AuthService.Api"
RUN dotnet publish "AuthService.Api.csproj" -c Release -o /app/publish --no-restore

# Stage 2: Create the final, smaller runtime image
# This stage creates the final image that will run your application
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Create a non-root user for better security
RUN adduser --disabled-password --gecos "" appuser
USER appuser

# Copy the published output from the build stage
COPY --from=build /app/publish .

# Expose the port your application will run on (e.g., for Render)
EXPOSE 10000

# Set the entry point for the application
ENTRYPOINT ["dotnet", "AuthService.Api.dll"]