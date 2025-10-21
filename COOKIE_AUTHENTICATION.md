# Cookie-Based Authentication Implementation

This document describes the cookie-based authentication implementation added to the Auth Service.

## Overview

The authentication system now supports storing JWT tokens in HTTP-only cookies for enhanced security. This prevents XSS attacks from accessing tokens stored in localStorage or sessionStorage.

## Features

### 1. Login with Cookies
- **Endpoint**: `POST /api/auth/login`
- **Behavior**: Sets access and refresh tokens as HTTP-only cookies
- **Response**: Returns user info without tokens in response body
- **Cookie Names**: `access_token` and `refresh_token` (configurable)

### 2. Token Refresh with Cookies
- **Endpoint**: `POST /api/auth/refresh`
- **Behavior**: Reads refresh token from cookie if not provided in request body
- **Response**: Updates access token cookie with new token

### 3. Logout with Cookie Clearing
- **Endpoint**: `POST /api/auth/logout`
- **Behavior**: Clears both access and refresh token cookies
- **Response**: Confirms successful logout

### 4. Automatic Token Reading
- JWT authentication middleware reads tokens from cookies automatically
- Falls back to Authorization header if cookie is not present
- Supports both cookie-based and header-based authentication

## Configuration

Cookie behavior is configurable through `appsettings.json`:

```json
{
  "CookieOptions": {
    "HttpOnly": true,
    "Secure": true,
    "SameSite": "Strict",
    "AccessTokenExpirationMinutes": 60,
    "RefreshTokenExpirationDays": 30,
    "AccessTokenName": "access_token",
    "RefreshTokenName": "refresh_token",
    "Domain": "",
    "Path": "/"
  }
}
```

### Configuration Options

- **HttpOnly**: Prevents client-side JavaScript access (recommended: `true`)
- **Secure**: Only send cookies over HTTPS (recommended: `true` for production)
- **SameSite**: CSRF protection (`Strict`, `Lax`, or `None`)
- **AccessTokenExpirationMinutes**: Access token cookie expiration
- **RefreshTokenExpirationDays**: Refresh token cookie expiration
- **AccessTokenName**: Name of access token cookie
- **RefreshTokenName**: Name of refresh token cookie
- **Domain**: Cookie domain (empty for current domain)
- **Path**: Cookie path (default: `/`)

## Security Benefits

1. **XSS Protection**: HTTP-only cookies cannot be accessed by JavaScript
2. **CSRF Protection**: SameSite attribute prevents cross-site requests
3. **Secure Transport**: Secure flag ensures cookies only sent over HTTPS
4. **Automatic Cleanup**: Cookies are automatically cleared on logout

## Usage Examples

### Frontend Integration

```javascript
// Login - tokens are automatically set in cookies
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
  credentials: 'include' // Important: include cookies
});

// Subsequent authenticated requests
const userResponse = await fetch('/api/auth/user/123', {
  credentials: 'include' // Cookies sent automatically
});

// Logout - cookies are automatically cleared
const logoutResponse = await fetch('/api/auth/logout', {
  method: 'POST',
  credentials: 'include'
});
```

### Multilingual Support

The implementation supports responses in multiple languages including:
- **English**: Standard error and success messages
- **Malayalam**: മലയാളം സന്ദേശങ്ങൾ
- **Manglish**: Malayalam written in English script

## Migration Notes

- Existing header-based authentication continues to work
- No breaking changes to API contracts
- Clients can choose between cookie or header authentication
- Both methods can be used simultaneously

## Development vs Production

### Development Settings
```json
{
  "CookieOptions": {
    "Secure": false,
    "SameSite": "Lax"
  }
}
```

### Production Settings
```json
{
  "CookieOptions": {
    "Secure": true,
    "SameSite": "Strict"
  }
}
```
