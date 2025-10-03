# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy the solution file and all project files to their correct locations
COPY ["AuthService.sln", "."]
COPY ["AuthService.Application/", "AuthService.Application/"]
COPY ["AuthService.Domain/", "AuthService.Domain/"]
COPY ["AuthService.Grpc/", "AuthService.Grpc/"]
COPY ["AuthService.Infrastructure/", "AuthService.Infrastructure/"]
COPY ["AuthService.Shared/", "AuthService.Shared/"]

# The API project is inside the 'AuthService' subfolder
COPY ["AuthService/", "AuthService/"]

# Restore dependencies for the entire solution
# This will now work because the folder structure is correct
RUN dotnet restore "AuthService.sln"

# Copy the rest of the source code (for any other files)
COPY . .

# Set the working directory to the API project folder to publish
WORKDIR "/src/AuthService"
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