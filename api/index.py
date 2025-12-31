import os
import uuid
import time
import requests
import random

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware

from jose import jwt
from agora_token_builder import RtcTokenBuilder
from pydantic import BaseModel
from dotenv import load_dotenv

# ✅ ADD THIS IMPORT (for Lambda)


# Load environment variables from .env file (local dev only)
load_dotenv()

# -------------------
# App setup
# -------------------

app = FastAPI()
security = HTTPBearer()
@app.get("/")
def root():
    return {"message": "Backend running on Vercel 🚀"}

@app.get("/health")
def health():
    return {"status": "ok"}

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------
# Request Models
# -------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class WhiteboardRequest(BaseModel):
    room_id: str


# -------------------
# Helpers
# -------------------
def verify_jwt(token: str):
    try:
        payload = jwt.decode(
            token,
            os.getenv("JWT_SECRET", "dev-secret-key-change-in-production"),
            algorithms=["HS256"]
        )
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def create_jwt(user_id: str):
    payload = {
        "id": user_id,
        "exp": int(time.time()) + 86400  # 24 hours
    }
    token = jwt.encode(
        payload,
        os.getenv("JWT_SECRET", "dev-secret-key-change-in-production"),
        algorithm="HS256"
    )
    return token


# -------------------
# Auth APIs
# -------------------
@app.post("/auth/login")
def login(req: LoginRequest):
    # Mock authentication
    user_id = str(uuid.uuid4())
    token = create_jwt(user_id)

    return {
        "token": token,
        "userId": user_id,
        "username": req.username
    }


# -------------------
# Room APIs
# -------------------
@app.post("/rooms")
def create_room(auth: HTTPAuthorizationCredentials = Depends(security)):
    user = verify_jwt(auth.credentials)

    room_id = str(uuid.uuid4())

    return {
        "roomId": room_id,
        "hostId": user["id"],
        "createdAt": int(time.time())
    }


@app.get("/rooms/{room_id}")
def get_room(room_id: str, auth: HTTPAuthorizationCredentials = Depends(security)):
    user = verify_jwt(auth.credentials)

    return {
        "roomId": room_id,
        "hostId": user["id"],
        "features": {
            "video": True,
            "whiteboard": True
        }
    }


# -------------------
# RTC Token API
# -------------------
@app.get("/rtc/token")
def rtc_token(
    channel: str,
    auth: HTTPAuthorizationCredentials = Depends(security)
):
    user = verify_jwt(auth.credentials)

    app_id = os.getenv("AGORA_APP_ID", "")
    app_cert = os.getenv("AGORA_APP_CERTIFICATE", "")

    if not app_id:
        raise HTTPException(
            status_code=500,
            detail="AGORA_APP_ID not configured"
        )

    expire_time = int(time.time()) + 3600
    agora_uid = random.randint(1, 2_000_000_000)

    if app_cert:
        token = RtcTokenBuilder.buildTokenWithUid(
            app_id,
            app_cert,
            channel,
            agora_uid,
            1,  # PUBLISHER
            expire_time
        )
    else:
        token = ""

    return {
        "token": token,
        "appId": app_id,
        "uid": agora_uid,
        "expiresIn": 3600
    }


# -------------------
# Whiteboard Session API
# -------------------
whiteboard_rooms = {}

@app.post("/whiteboard/session")
def whiteboard_session(
    request: WhiteboardRequest,
    auth: HTTPAuthorizationCredentials = Depends(security)
):
    user = verify_jwt(auth.credentials)
    room_id = request.room_id

    whiteboard_sk = os.getenv("WHITEBOARD_SK", "")
    whiteboard_app_id = os.getenv("WHITEBOARD_APP_ID", "")

    if not whiteboard_sk or not whiteboard_app_id:
        raise HTTPException(
            status_code=500,
            detail="Whiteboard environment variables not configured"
        )

    whiteboard_sk = whiteboard_sk.strip().strip('"').strip("'")

    try:
        # Reuse or create whiteboard room
        if room_id in whiteboard_rooms:
            room_uuid = whiteboard_rooms[room_id]
        else:
            room_resp = requests.post(
                "https://api.netless.link/v5/rooms",
                headers={
                    "token": whiteboard_sk,
                    "Content-Type": "application/json",
                    "region": "us-sv"
                },
                json={"isRecord": False},
                timeout=10
            )

            if room_resp.status_code != 201:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to create whiteboard room: {room_resp.text}"
                )

            room_uuid = room_resp.json()["uuid"]
            whiteboard_rooms[room_id] = room_uuid

        # Create room token
        token_resp = requests.post(
            f"https://api.netless.link/v5/tokens/rooms/{room_uuid}",
            headers={
                "token": whiteboard_sk,
                "Content-Type": "application/json",
                "region": "us-sv"
            },
            json={
                "lifespan": 3600000,
                "role": "admin"
            },
            timeout=10
        )

        if token_resp.status_code != 201:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create whiteboard token: {token_resp.text}"
            )

        return {
            "roomUUID": room_uuid,
            "roomToken": token_resp.text.strip('"'),
            "appIdentifier": whiteboard_app_id,
            "region": "us-sv"
        }

    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Network error: {str(e)}"
        )


# =====================================================
# ✅ REQUIRED FOR AWS LAMBDA (DO NOT REMOVE)
# =====================================================

