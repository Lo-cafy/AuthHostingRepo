# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy csproj files and restore dependencies
COPY ["AuthService/AuthService.Api.csproj", "AuthService/"]
COPY ["AuthService.Application/AuthService.Application.csproj", "AuthService.Application/"]
COPY ["AuthService.Domain/AuthService.Domain.csproj", "AuthService.Domain/"]
COPY ["AuthService.Infrastructure/AuthService.Infrastructure.csproj", "AuthService.Infrastructure/"]
COPY ["AuthService.Grpc/AuthService.Grpc.csproj", "AuthService.Grpc/"]
COPY ["AuthService.Shared/AuthService.Shared.csproj", "AuthService.Shared/"]

RUN dotnet restore "AuthService/AuthService.Api.csproj"

# Copy everything else
COPY . .

WORKDIR "/src/AuthService"

RUN dotnet build "AuthService.Api.csproj" -c Release -o /app/build /p:UseAppHost=false

# Publish stage
FROM build AS publish
RUN dotnet publish "AuthService.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app

# Create non-root user
RUN adduser --disabled-password --gecos "" appuser 
RUN	chown -R appuser /app
USER appuser

COPY --from=publish /app/publish .
EXPOSE 8080
ENTRYPOINT ["dotnet", "AuthService.Api.dll"]
# docker-compose -f docker-compose.auth-service.yml up --build
