"""
Minimal stand-in for a real identity/auth microservice. Its only job here
is to issue a JWT the gateway can validate, and to deliberately accept a
FIXED demo credential so the attack-simulation scripts have something to
brute-force -- that's what makes the credential-stuffing demo meaningful.

Do not use this as-is anywhere near production: no password hashing, no
lockout, no rate limiting of its own (that is precisely the gateway's
job, which is the point of this whole project).
"""
import os
import time

import jwt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="mock-auth-service")

JWT_SECRET = os.environ["JWT_SECRET"]
DEMO_USERNAME = "demo_user"
DEMO_PASSWORD = "correct-horse-battery-staple"


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(req: LoginRequest):
    if req.username == DEMO_USERNAME and req.password == DEMO_PASSWORD:
        token = jwt.encode({"sub": req.username, "iat": int(time.time())}, JWT_SECRET, algorithm="HS256")
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/auth/register")
def register():
    return {"status": "registration disabled in demo"}


@app.get("/health")
def health():
    return {"status": "ok"}
