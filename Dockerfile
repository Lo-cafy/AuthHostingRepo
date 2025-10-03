# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy all .csproj files and the .sln file to their correct locations
COPY ["AuthService.sln", "."]
COPY ["AuthService.Api.csproj", "."] # This file is in the root
COPY ["AuthService.Application/AuthService.Application.csproj", "AuthService.Application/"]
COPY ["AuthService.Domain/AuthService.Domain.csproj", "AuthService.Domain/"]
COPY ["AuthService.Infrastructure/AuthService.Infrastructure.csproj", "AuthService.Infrastructure/"]
COPY ["AuthService.Grpc/AuthService.Grpc.csproj", "AuthService.Grpc/"]
COPY ["AuthService.Shared/AuthService.Shared.csproj", "AuthService.Shared/"]

# Restore dependencies for the entire solution
RUN dotnet restore "AuthService.sln"

# Copy the rest of the source code
COPY . .

# Publish the main API project from the root
RUN dotnet publish "AuthService.Api.csproj" -c Release -o /app/publish --no-restore

# Stage 2: Create the final, smaller runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Create a non-root user for better security
RUN adduser --disabled-password --gecos "" appuser
USER appuser

# Copy the published output from the build stage
COPY --from=build /app/publish .

# Expose the port your application will run on
EXPOSE 10000

# Set the entry point for the application
ENTRYPOINT ["dotnet", "AuthService.Api.dll"]