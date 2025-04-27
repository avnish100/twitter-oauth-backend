from fastapi import FastAPI, HTTPException, Request, Response, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import httpx
import hashlib
import base64
import secrets
import os
from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier
from fastapi_sessions.frontends.implementations import SessionCookie, CookieParameters
from uuid import UUID, uuid4
from typing import Optional

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

X_CLIENT_ID = os.getenv("X_CLIENT_ID", "X1Boc0c3SW5lclhIZVpOTXY4TEw6MTpjaQ")
X_CLIENT_SECRET = os.getenv("X_CLIENT_SECRET", "MBMsBOkx1IFO6Ky5ycvFiy8YqP1WWPxHAWcCiGCRoppLwlrGmZ")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/api/auth/x/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Session management
class SessionData(BaseModel):
    code_verifier: str
    state: str
    is_verified: bool = False
    user_id: Optional[str] = None
    username: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    profile_image_url: Optional[str] = None
    created_at: Optional[str] = None

# cookie
cookie_params = CookieParameters(
    cookie_name="x_auth_session",
    secure=False,
    httponly=True,
    samesite="lax",
    max_age=1800
)

SECRET_KEY = os.getenv("SECRET_KEY", "a3baede2adbd9bc5ed56fdfe096b3e778a5d58708e5c60b5841d07853ac0514e")

backend = InMemoryBackend[UUID, SessionData]()


cookie = SessionCookie(
    cookie_name="x_auth_session",
    identifier="general_verifier",
    auto_error=True,
    secret_key=SECRET_KEY,
    cookie_params=cookie_params,
)


class BasicVerifier(SessionVerifier[UUID, SessionData]):
    def __init__(
        self,
        *,
        identifier: str,
        auto_error: bool,
        backend: InMemoryBackend[UUID, SessionData],
        auth_http_exception: HTTPException,
    ):
        self._identifier = identifier
        self._auto_error = auto_error
        self._backend = backend
        self._auth_http_exception = auth_http_exception

    @property
    def identifier(self):
        return self._identifier

    @property
    def backend(self):
        return self._backend

    @property
    def auto_error(self):
        return self._auto_error

    @property
    def auth_http_exception(self):
        return self._auth_http_exception

    def verify_session(self, model: SessionData) -> bool:
        """Verify the session data."""
        return model.is_verified

verifier = BasicVerifier(
    identifier="general_verifier",
    auto_error=True,
    backend=backend,
    auth_http_exception=HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid session",
    ),
)

# PKCE utility functions
# Generate a code verifier and code challenge for PKCE
def generate_code_verifier(length: int = 64) -> str:
    """Generate a code verifier for PKCE."""
    code_verifier = secrets.token_urlsafe(length)
    return code_verifier

def generate_code_challenge(code_verifier: str) -> str:
    """Generate a code challenge for PKCE."""
    code_challenge = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode().rstrip("=")
    return code_challenge

@app.get("/api/auth/x/login")
async def login():
    """Start the X OAuth flow with PKCE."""
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    state = secrets.token_urlsafe(16)
    
    session_id = uuid4()
    session_data = SessionData(code_verifier=code_verifier, state=state)
    await backend.create(session_id, session_data)
    
    # Build the authorization URL with PKCE parameters
    auth_url = "https://twitter.com/i/oauth2/authorize"
    params = {
        "response_type": "code",
        "client_id": X_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "tweet.read users.read users.email offline.access",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "force_login": "true"
    }
    
    # Format parameters
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    
    # Return the authorization URL with parameters
    response = RedirectResponse(url=f"{auth_url}?{query_string}")
    cookie.attach_to_response(response, session_id)
    return response

@app.get("/api/auth/x/callback")
async def callback(
    request: Request,
    code: str = None,
    state: str = None,
    error: str = None,
    session_id: UUID = Depends(cookie),
):
    """Handle the callback from X OAuth."""
    # Check for errors
    if error:
        return RedirectResponse(f"{FRONTEND_URL}/auth-error?error={error}")
    
    # Get session data
    session_data = await backend.read(session_id)
    
    # Verify state parameter
    if not state or state != session_data.state:
        return RedirectResponse(f"{FRONTEND_URL}/auth-error?error=invalid_state")
    
    # Exchange code for token using the code verifier
    try:
        async with httpx.AsyncClient() as client:
            token_url = "https://api.twitter.com/2/oauth2/token"
            auth_str = f"{X_CLIENT_ID}:{X_CLIENT_SECRET}"
            auth_bytes = auth_str.encode("ascii")
            auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
            
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": session_data.code_verifier
            }
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {auth_b64}"
            }
            
            token_response = await client.post(token_url, data=data, headers=headers)
            token_data = token_response.json()
            
            if token_response.status_code != 200:
                return RedirectResponse(f"{FRONTEND_URL}/auth-error?error=token_error&details={token_data.get('error', 'unknown')}")
            
            access_token = token_data["access_token"]
            
            # Get user information
            user_url = "https://api.twitter.com/2/users/me"
            user_params = {
                "user.fields": "id,name,username,profile_image_url,created_at"
            }
            user_headers = {
                "Authorization": f"Bearer {access_token}"
            }
            
            user_response = await client.get(user_url, params=user_params, headers=user_headers)
            user_data = user_response.json()
            
            if user_response.status_code != 200:
                return RedirectResponse(f"{FRONTEND_URL}/auth-error?error=user_info_error")
            
            # Get user email
            email_url = "https://api.twitter.com/2/users/me"
            email_params = {
                "user.fields": "email"
            }
            email_headers = {
                "Authorization": f"Bearer {access_token}"
            }
            
            email_response = await client.get(email_url, params=email_params, headers=email_headers)
            email_data = email_response.json()
            
            # Update session with verification and user info
            user_info = user_data["data"]
            session_data.is_verified = True
            session_data.user_id = user_info["id"]
            session_data.username = user_info["username"]
            session_data.name = user_info["name"]
            session_data.profile_image_url = user_info.get("profile_image_url")
            session_data.created_at = user_info.get("created_at")
            session_data.email = email_data["data"].get("email") if email_response.status_code == 200 else None
            
            await backend.update(session_id, session_data)
            
            # Redirect to frontend success page
            return RedirectResponse(f"{FRONTEND_URL}/verification-success")
    
    except Exception as e:
        return RedirectResponse(f"{FRONTEND_URL}/auth-error?error=server_error&details={str(e)}")

@app.get("/api/auth/session")
async def get_session_info(
    session_id: UUID = Depends(cookie),
    session_data: SessionData = Depends(verifier)
):
    """Get the current session information."""
    if not session_data.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not authenticated"
        )
    print(session_data)
    return {
        "is_verified": session_data.is_verified,
        "user_id": session_data.user_id,
        "username": session_data.username,
        "name": session_data.name,
        "email": session_data.email,
        "profile_image_url": session_data.profile_image_url,
        "created_at": session_data.created_at
    }

@app.post("/api/auth/logout")
async def logout(response: Response, session_id: UUID = Depends(cookie)):
    """End the session and clear the cookie."""
    await backend.delete(session_id)
    cookie.delete_from_response(response)
    return {"message": "Logged out successfully"}

@app.get("/")
def read_root():
    return {"message": "X OAuth API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)