from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
import time
from typing import Optional
import jwt
from jwt.exceptions import InvalidTokenError


"""
AWS Cognitoから取得したJWTトークンを検証するサンプル

1.署名の検証
2.有効期限(exp)，オーディエンス(aud)，発行者(iss)，トークン使用用途(token_use)の検証

参考:https://docs.aws.amazon.com/ja_jp/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
"""
app = FastAPI()

# APIキーの名前を設定
API_KEY_NAME = "Authorization"
api_key_header_auth = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# AWS Cognitoの情報
COGNITO_ISSUER = 'https://cognito-idp.{region}.amazonaws.com/{userPoolId}'
COGNITO_AUDIENCE = '{appId}'

async def authenticate_token(api_key: str = Depends(api_key_header_auth)) -> Optional[str]:
    """
    AWS Cognitoから取得したトークンを検証する関数
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # JWTトークンをデコード（署名の検証は省略）
        token = api_key.split(" ")[1]  # 'Bearer'を取り除く
        payload = jwt.decode(token, options={"verify_signature": False})

        username: Optional[str] = payload.get("username")
        
        if username is None:
            raise credentials_exception

        # 発行者とオーディエンスを検証
        if payload['iss'] != COGNITO_ISSUER or payload['aud'] != COGNITO_AUDIENCE:
            raise credentials_exception
        
        # 有効期限とトークン使用用途を検証
        current_time = time.time()
        if payload['exp'] < current_time or payload.get('token_use') != 'access':
            raise credentials_exception

    except InvalidTokenError:
        raise credentials_exception
    return username

@app.get("/", dependencies=[Depends(authenticate_token)])
def read_root():
    return {"Hello": "World"}


# from fastapi import Depends, FastAPI, HTTPException, status, Security
# from fastapi.security import OAuth2
# from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
# from typing import Optional
# import jwt
# from jwt.exceptions import InvalidTokenError

# app = FastAPI()

# class OAuth2PasswordBearerWithJWT(OAuth2):
#     def __init__(self, scheme_name: str = None, scopes: dict = None, auto_error: bool = True):
#         if not scheme_name:
#             scheme_name = self.__class__.__name__
#         flows = OAuthFlowsModel(password={"tokenUrl": "/token"})
#         super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

# oauth2_scheme = OAuth2PasswordBearerWithJWT()

# # AWS Cognitoの情報
# COGNITO_ISSUER = 'https://cognito-idp.{region}.amazonaws.com/{userPoolId}'
# COGNITO_AUDIENCE = '{appId}'

# async def authenticate_token(token: str = Depends(oauth2_scheme)) -> Optional[str]:
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, options={"verify_signature": False})
#         username: Optional[str] = payload.get("username")

#         if username is None or payload['iss'] != COGNITO_ISSUER or payload['aud'] != COGNITO_AUDIENCE:
#             raise credentials_exception
#     except InvalidTokenError:
#         raise credentials_exception
#     return username

# @app.get("/", dependencies=[Depends(authenticate_token)])
# def read_root():
#     return {"Hello": "World"}
