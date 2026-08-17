# FastAPI Security Middleware
# Add to your main.py

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://oneresume.life"],  # Replace with your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted Host Middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["oneresume.life", "api.oneresume.life", "*.oneresume.life"]
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Add security headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Remove server header
    if "server" in response.headers:
        del response.headers["server"]
    
    return response

# Rate Limiting Middleware
from collections import defaultdict
import asyncio

request_counts = defaultdict(list)

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    client_ip = request.client.host
    now = time.time()
    
    # Clean old requests
    request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < 60]
    
    # Check rate limit
    if len(request_counts[client_ip]) > 100:  # 100 requests per minute
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests"}
        )
    
    request_counts[client_ip].append(now)
    return await call_next(request)

# Disable OpenAPI in production
@app.get("/openapi.json", include_in_schema=False)
async def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    # Return 404 in production
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Not found")
