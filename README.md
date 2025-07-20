# Auth Backend System (Node.js + Express.js)

This is a simple authentication backend with user signup, login, OTP verification, and JWT-based token authentication using cookies.

## Features
- User signup with OTP verification
- Login with email or mobile
- JWT-based access and refresh tokens
- Tokens stored in HTTP-only cookies
- Middleware for route protection

## Endpoints

- POST /signup
- POST /verify-otp
- POST /login
- POST /refresh-token
- GET /protected (requires login)

## How to Run

```bash
npm install
node index.js
