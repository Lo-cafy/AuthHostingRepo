@echo off
echo Starting Auth Service with Swagger...
cd /d "d:\SingleProject1\BACKEND\AuthHostingRepo"
echo Killing any existing processes...
taskkill /F /IM AuthService.Api.exe 2>nul
taskkill /F /IM dotnet.exe 2>nul
timeout /t 2 /nobreak >nul
echo Starting application on port 7182...
dotnet run --project AuthService --urls https://localhost:7182
pause
