"""App for Duka Auth Project."""
import logging
import sys
from typing import Any, Dict, Union

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import ORJSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from loguru import logger
from starlette.middleware.cors import CORSMiddleware

from .logger import InterceptHandler, log_format
from .models import (
    ChangeEmail,
    ChangePassword,
    EmailVerifyConfirm,
    HasuraEventTrigger,
    PasswordReset,
    PasswordResetConfirm,
    SignIn,
    SignInOutput,
    Signup,
    CreateManager,
)
from .schema import CHANGE_USER_EMAIL, FIND_USER, GET_USER
from .services import (
    add_employ,
    authenticate,
    change_password,
    confirm_password_reset,
    create_user,
    generate_email_verification,
    generate_password_reset,
    graphql,
    update_last_login,
    verify_email,
)
from .settings import REDIS, SETTINGS, EnvSettings

app = FastAPI(
    title=SETTINGS.PROJECT_NAME,
    description=SETTINGS.PROJECT_DESCRIPTION,
    version="0.1.0",
    docs_url=SETTINGS.DOCS_URL,
    redoc_url=SETTINGS.REDOC_URL,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=SETTINGS.CORS_ORIGINS,
    allow_credentials=SETTINGS.CORS_ALLOW_CREDENTIALS,
    allow_methods=SETTINGS.CORS_ALLOW_METHODS,
    allow_headers=SETTINGS.CORS_ALLOW_HEADERS,
)


@AuthJWT.load_config
def get_config() -> EnvSettings:
    """A callback to get your configuration."""
    return SETTINGS


@app.exception_handler(AuthJWTException)
def auth_exception_handler(request: Request, exc: AuthJWTException) -> ORJSONResponse:
    """Exception handler for authjwt."""
    return ORJSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@AuthJWT.token_in_denylist_loader
def check_if_token_in_deny_list(
    decrypted_token: Dict[str, Any]
) -> Union[str, None, bool]:
    """Checking if the tokens jti is in the deny list set."""
    jti = decrypted_token["jti"]
    entry = REDIS.get(jti)
    return entry and entry == "true"


@app.post("/signup/", response_class=ORJSONResponse)
async def sign_up(user_input: Signup) -> Dict[str, str]:
    """Sign up new users."""
    data = await create_user(data=user_input.input.data)
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User already existed.")
    return {"detail": "user has been created"}


@app.post("/sign-in/", response_class=ORJSONResponse, response_model=SignInOutput)
async def sign_in(
    background_tasks: BackgroundTasks,
    user_input: SignIn,
    authorize: AuthJWT = Depends(),
) -> SignInOutput:
    """Sign in a user."""
    user = await authenticate(data=user_input.input.data)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    organization_id = user.employs[0].get("organization") if user.employs else ""

    hasura_claims = {
        "https://hasura.io/jwt/claims": {
            "x-hasura-user-id": f"{user.id}",
            "x-hasura-default-role": user.role,
            "x-hasura-allowed-roles": [user.role],
            "x-hasura-is-active": f"{user.is_active}",
            "x-hasura-is-email-verified": f"{user.is_email_verified}",
            "x-hasura-organization-id": organization_id,
        }
    }

    access_token = authorize.create_access_token(
        subject=f"{user.id}", fresh=True, user_claims=hasura_claims
    )

    refresh_token = authorize.create_refresh_token(
        subject=f"{user.id}",
        user_claims={
            "https://hasura.io/jwt/claims": {
                "x-hasura-default-role": "refresh_token",
                "x-hasura-allowed-roles": ["refresh_token"],
            },
            "access_token_claims": hasura_claims,
        },
    )

    background_tasks.add_task(
        update_last_login,
        user_id=f"{user.id}",
    )

    return SignInOutput(  # noqa S106
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@app.post("/refresh", response_class=ORJSONResponse)
def refresh(
    background_tasks: BackgroundTasks, authorize: AuthJWT = Depends()
) -> Dict[str, str]:
    """The jwt_refresh_token_required() function insures. a valid refresh.

    token is present in the request before running any code below that function.
    we can use the get_jwt_subject() function to get the subject of the refresh
    token, and use the create_access_token() function again to make a new access token

    Args:
        authorize: A Depends that use the auth jwt from FastAPI JWT Auth.
        background_tasks: A FastAPI class to handle background tasks.

    Returns:
        New access token.
    """
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()

    raw_jwt = authorize.get_raw_jwt()

    new_access_token = authorize.create_access_token(
        subject=current_user,
        fresh=False,
        user_claims=raw_jwt.get("access_token_claims"),
    )

    background_tasks.add_task(
        update_last_login,
        user_id=current_user,
    )

    return {"access_token": new_access_token}


@app.post("/access-revoke", response_class=ORJSONResponse)
def access_revoke(authorize: AuthJWT = Depends()) -> Dict[str, str]:
    """Revoking the current users access token."""
    authorize.jwt_required()
    jti = authorize.get_raw_jwt()["jti"]
    REDIS.setex(jti, SETTINGS.authjwt_access_token_expires, "true")
    return {"detail": "Access token has been revoke"}


@app.post("/refresh-revoke", response_class=ORJSONResponse)
def refresh_revoke(authorize: AuthJWT = Depends()) -> Dict[str, str]:
    """Revoking the current users refresh token."""
    authorize.jwt_refresh_token_required()

    jti = authorize.get_raw_jwt()["jti"]
    REDIS.setex(jti, SETTINGS.authjwt_refresh_token_expires, "true")

    return {"detail": "Refresh token has been revoke"}


@app.post("/change-password", response_class=ORJSONResponse)
async def change_user_password(
    user_input: ChangePassword, authorize: AuthJWT = Depends()
) -> Dict[str, str]:
    """Change the current user password."""
    authorize.jwt_required()
    user_id = authorize.get_jwt_subject()

    if await change_password(data=user_input.input.data, user_id=user_id):
        return {"detail": "Password has been changed"}

    return {"detail": "Incorrect password"}


@app.post("/password-reset", response_class=ORJSONResponse)
async def password_reset(
    user_input: PasswordReset, background_tasks: BackgroundTasks
) -> Dict[str, str]:
    """Change the current user password."""
    background_tasks.add_task(
        generate_password_reset,
        email=user_input.input.data.email,
    )

    return {"detail": "Password reset e-mail has been sent."}


@app.post("/password-reset-confirm", response_class=ORJSONResponse)
async def password_reset_confirm(user_input: PasswordResetConfirm) -> Dict[str, str]:
    """Confirm password reset."""
    if await confirm_password_reset(
        email=user_input.input.data.email,
        token=user_input.input.data.token,
        password=user_input.input.data.password,
    ):

        return {"detail": "Password has changed."}

    return {"detail": "The token has expired."}


@app.post("/send-email-verification", response_class=ORJSONResponse)
async def send_email_verification(event_data: HasuraEventTrigger) -> None:
    """Send email verification."""
    await generate_email_verification(data=event_data.event.data.new)


@app.post("/email-verify", response_class=ORJSONResponse)
async def email_verify(
    user_input: EmailVerifyConfirm, authorize: AuthJWT = Depends()
) -> Dict[str, str]:
    """Email verify."""
    authorize.jwt_required()

    user_id = authorize.get_jwt_subject()

    if await verify_email(user_id=user_id, token=user_input.input.data.token):

        return {"detail": "Your account account has been verified."}

    return {"detail": "The token has expired."}


@app.post("/change-email", response_class=ORJSONResponse)
async def change_email(
    background_tasks: BackgroundTasks,
    user_input: ChangeEmail,
    authorize: AuthJWT = Depends(),
) -> Dict[str, str]:
    """Change user email."""
    authorize.jwt_required()

    user_id = authorize.get_jwt_subject()

    new_email = user_input.input.data.email

    r = await graphql(
        query=FIND_USER,
        variables={"email": new_email, "username": ""},
    )

    users = r.json().get("data").get("users")

    if len(users) > 0:
        return {"detail": "Account with this email already exists."}

    await graphql(
        query=CHANGE_USER_EMAIL
        % {
            "user_id": user_id,
            "email": new_email,
        }
    )

    r = await graphql(query=GET_USER % user_id)

    user_data = r.json().get("data").get("users_by_pk")

    background_tasks.add_task(
        generate_email_verification,
        data=user_data,
    )

    return {"detail": "The email has been changed, email verify e-mail has been sent."}


@app.post("/resend-email-verification", response_class=ORJSONResponse)
async def resend_email_verification(
    background_tasks: BackgroundTasks,
    authorize: AuthJWT = Depends(),
) -> Dict[str, str]:
    """Resend email verification."""
    authorize.jwt_required()

    user_id = authorize.get_jwt_subject()

    r = await graphql(query=GET_USER % user_id)

    user_data = r.json().get("data").get("users_by_pk")

    if user_data.get("is_email_verified"):
        return {"detail": "You Email already verified!"}

    background_tasks.add_task(
        generate_email_verification,
        data=user_data,
    )

    return {"detail": "Email verify e-mail has been sent."}


@app.post("/create-operator/", response_class=ORJSONResponse)
async def create_operator(user_input: Signup) -> Dict[str, str]:
    """Create new operator."""
    data = await create_user(data=user_input.input.data, role="operator")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Operator already existed.")
    return {"detail": "Operator has been created"}


@app.post("/create-manager/", response_class=ORJSONResponse)
async def create_manager(user_input: CreateManager) -> Dict[str, str]:
    """Create new manager."""
    data = await create_user(data=user_input.input.data, role="manager")

    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Manager already existed.")

    user_id = data.get("resp").json().get("data").get("insert_users_one").get("id")

    await add_employ(user_id=user_id, organization_id=user_input.input.data.organization)

    return {"detail": "Manager has been created"}


@app.post("/create-driver/", response_class=ORJSONResponse)
async def create_driver(user_input: Signup, authorize: AuthJWT = Depends()) -> Dict[str, str]:
    """Create new driver."""
    authorize.jwt_required()

    raw_jwt = authorize.get_raw_jwt()

    organization_id = raw_jwt.get("https://hasura.io/jwt/claims").get("x-hasura-organization-id")

    data = await create_user(data=user_input.input.data, role="driver")

    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Driver already existed.")

    user_id = data.get("resp").json().get("data").get("insert_users_one").get("id")

    await add_employ(user_id=user_id, organization_id=organization_id)

    return {"detail": "Driver has been created"}


@app.post("/create-ticketer/", response_class=ORJSONResponse)
async def create_ticketer(user_input: Signup, authorize: AuthJWT = Depends()) -> Dict[str, str]:
    """Create new ticketer."""
    authorize.jwt_required()

    raw_jwt = authorize.get_raw_jwt()

    organization_id = raw_jwt.get("https://hasura.io/jwt/claims").get("x-hasura-organization-id")

    data = await create_user(data=user_input.input.data, role="ticketer")

    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Ticketer already existed.")

    user_id = data.get("resp").json().get("data").get("insert_users_one").get("id")

    await add_employ(user_id=user_id, organization_id=organization_id)

    return {"detail": "Ticketer has been created"}


logging.getLogger().handlers = [InterceptHandler()]
logger.configure(
    handlers=[
        {
            "sink": sys.stdout,
            "level": SETTINGS.LOG_LEVEL,
            "format": log_format,
        }
    ]
)
logger.add("logs/file_{time:YYYY-MM-DD}.log", level="TRACE", rotation="1 day")

logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]
