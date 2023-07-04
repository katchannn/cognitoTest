from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
import time
from typing import Optional
import jwt
from jwt.exceptions import InvalidTokenError

app = FastAPI()

# Cognitoの設定
COGNITO_ISSUER = "https://cognito-idp.{region}.amazonaws.com/{userPoolId}"
COGNITO_AUDIENCE = "{appId}"
TOKEN_USE = "access"
EXPIRATION_TIME = 3600

# APIの設定
API_KEY_NAME = "Authorization"
api_key_header_auth = APIKeyHeader(name=API_KEY_NAME, auto_error=True)


def create_token(
    username: str,
    secret: str,
    issuer: str = COGNITO_ISSUER,
    audience: str = COGNITO_AUDIENCE,
    token_use: str = TOKEN_USE,
) -> str:
    """
    トークンの作成
    """
    payload = {
        "username": username,
        "iss": issuer,
        "aud": audience,
        "exp": int(time.time()) + EXPIRATION_TIME,
        "token_use": token_use,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


# デモ用のトークン作成
username = "your_username"
secret = "your_secret"
token = create_token(username, secret)
print(token)


async def authenticate_token(
    api_key: str = Depends(api_key_header_auth), secret_key: str = secret
) -> Optional[str]:
    """
    トークン検証
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = api_key.split(" ")[1]  # Remove 'Bearer'
        print(token)
        print(secret_key)
        payload = jwt.decode(
            token, secret_key, algorithm="HS256", options={"verify_exp": False}
        )
        print(payload)

        username = payload.get("username")
        if (
            not username
            or payload["iss"] != COGNITO_ISSUER
            or payload["aud"] != COGNITO_AUDIENCE
            or payload["exp"] < time.time()
            or payload["token_use"] != TOKEN_USE
        ):
            raise credentials_exception

    except jwt.InvalidTokenError:
        raise credentials_exception

    return username


@app.get("/test", dependencies=[Depends(authenticate_token)])
def test():
    return {"Congratulations!!!": "You are authenticated"}
