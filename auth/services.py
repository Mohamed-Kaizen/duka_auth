"""Collection of services."""
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional

import httpx

from .models import ChangePasswordData, SignInData, SignupData, UserModel
from .schema import (
    CHANGE_USER_PASSWORD,
    CREATE_USER,
    FIND_USER,
    GET_USER,
    LAST_LOGIN,
    VERIFY_USER_EMAIL,
    ADD_EMPLOY,
)
from .settings import SETTINGS
from .utils import default_token_generator, make_password_hash, verify_password


async def graphql(*, query: str, variables: Optional[Dict] = None) -> httpx.Response:
    """Execute a graphql query."""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            SETTINGS.HASURA_ENDPOINT_URL,
            json={
                "query": query,
                "variables": variables,
            },
            headers={"x-hasura-admin-secret": SETTINGS.HASURA_GRAPHQL_ADMIN_SECRET},
        )
        return r


async def user_exists(*, username: str, phone_number: str) -> bool:
    """Checking if the user existed or not."""
    r = await graphql(
        query=FIND_USER,
        variables={
            "username": username,
            "phone_number": phone_number,
        },
    )
    return len(r.json().get("data").get("users")) > 0


async def create_user(*, data: SignupData, role: str = "user") -> dict:
    """Create new user.

    Args:
        data: Dict of new user info.

    Returns:
        true if user has been created, otherwise false.
    """
    if await user_exists(username=data.username, phone_number=data.phone_number):
        return False

    password = make_password_hash(password=data.password)

    resp = await graphql(
        query=CREATE_USER,
        variables={
            "email": data.email,
            "username": data.username,
            "first_name": data.first_name,
            "last_name": data.last_name,
            "password": password,
            "gender": data.gender,
            "role": role,
            "phone_number": data.phone_number,
            "last_login": f"{datetime.now()}",
        },
    )

    return {"created": True, "resp": resp}


async def authenticate(*, data: SignInData) -> Optional[UserModel]:
    """Authenticate function.

    Args:
        data: Dict of new user info.

    Returns:
        user or None
    """
    r = await graphql(
        query=FIND_USER,
        variables={
            "username": data.username,
            "phone_number": data.phone_number,
        },
    )

    user_data = r.json().get("data").get("users")
    print("^" * 50)
    print(user_data)

    if len(user_data) == 0:
        return None

    user = UserModel(**user_data[0])
    print("^" * 50)
    print(user)
    if not verify_password(plain_password=data.password, hashed_password=user.password):
        return None

    return user


async def change_password(*, data: ChangePasswordData, user_id: str) -> bool:
    """Changing the current login user password."""
    r = await graphql(query=GET_USER % user_id)

    password = r.json().get("data").get("users_by_pk").get("password")

    if not verify_password(plain_password=data.old_password, hashed_password=password):
        return False

    await graphql(
        query=CHANGE_USER_PASSWORD
        % {
            "user_id": user_id,
            "new_password": make_password_hash(password=data.new_password),
        }
    )

    return True


def send_email(
    *, subject: str, receiver_email: str, plain_text: str, html: str
) -> None:
    """Reusable function to send email."""
    try:
        msg = MIMEMultipart("alternative")

        msg["Subject"] = subject

        msg["From"] = SETTINGS.EMAIL_USER

        msg["To"] = receiver_email

        part1 = MIMEText(plain_text, "plain")

        part2 = MIMEText(html, "html")

        msg.attach(part1)

        msg.attach(part2)

        with smtplib.SMTP(SETTINGS.SMTP_HOST_ADDR, SETTINGS.SMTP_HOST_PORT) as smtp:
            smtp.ehlo()

            smtp.starttls()

            smtp.login(SETTINGS.EMAIL_USER, SETTINGS.EMAIL_PASSWORD)

            smtp.send_message(msg)

    except Exception as error:
        print(error)


async def generate_password_reset(*, email: str) -> None:
    """Generate password reset and send it by email."""
    r = await graphql(query=FIND_USER, variables={"email": email, "username": ""})
    user_data = r.json().get("data").get("users")

    if len(user_data) > 0:
        user = UserModel(**user_data[0])
        token = default_token_generator.make_token(user)
        plain_text = f"""\
    Hey {user.username},
    Your Duka account password can be reset by clicking the link below. 
    If you did not request a new password, please ignore this email.
    
    {SETTINGS.PASSWORD_RESET_CALLBACK_URL}?token={token}&email={email}
    """
        html = f"""\
    <html>
      <body>
        <h1>Hey {user.username},<br>
        Your Duka account password can be reset by clicking the link below. 
        If you did not request a new password, please ignore this email.
        <a href="{SETTINGS.PASSWORD_RESET_CALLBACK_URL}?token={token}&email={email}">
            Reset Password
        </a>
        </h1>
      </body>
    </html>
    """

        send_email(
            subject="Password Reset Request for Duka",
            receiver_email=email,
            plain_text=plain_text,
            html=html,
        )


async def confirm_password_reset(*, email: str, token: str, password: str) -> bool:
    """Confirm password reset."""
    r = await graphql(query=FIND_USER, variables={"email": email, "username": ""})

    user_data = r.json().get("data").get("users")

    if len(user_data) > 0:

        user = UserModel(**user_data[0])

        if default_token_generator.check_token(user, token):

            rep = await graphql(
                query=CHANGE_USER_PASSWORD
                % {
                    "user_id": user.id,
                    "new_password": make_password_hash(password=password),
                }
            )

            return "errors" not in rep.json()

        return False


async def generate_email_verification(*, data: Dict) -> None:
    """Generate email verification and send it by email."""
    user = UserModel(**data)
    token = default_token_generator.make_token(user)
    plain_text = f"""\
Hey,
Verify this email address for your Duka account by clicking the link below. 
If you did not request to verify a Duka account, you can safely ignore this email.

{SETTINGS.EMAIL_VERIFY_CALLBACK_URL}?token={token}
"""
    html = f"""\
<html>
  <body>
    <h1>Hey,<br>
    Verify this email address for your Duka account by clicking the link below.  
    If you did not request to verify a Duka account, you can safely ignore this email.
    <a href="{SETTINGS.EMAIL_VERIFY_CALLBACK_URL}?token={token}">
        Verify Email Address Now
    </a>
    </h1>
  </body>
</html>
"""

    send_email(
        subject="Verify Your Email",
        receiver_email=data.get("email"),
        plain_text=plain_text,
        html=html,
    )


async def verify_email(*, user_id: str, token: str) -> bool:
    """Verify email."""
    r = await graphql(query=GET_USER % user_id)

    if "errors" in r.json():
        return False

    user_data = r.json().get("data").get("users_by_pk")

    user = UserModel(**user_data)

    if default_token_generator.check_token(user, token):
        rep = await graphql(
            query=VERIFY_USER_EMAIL
            % {
                "user_id": user.id,
                "is_email_verified": True,
            }
        )

        return "errors" not in rep.json()

    return False


async def update_last_login(*, user_id: str) -> None:
    """Update user last login."""
    await graphql(
        query=LAST_LOGIN
        % {
            "user_id": user_id,
            "last_login": f"{datetime.now()}",
        }
    )


async def add_employ(*, user_id: str, organization_id: str) -> None:
    """Update user last login."""
    await graphql(
        query=ADD_EMPLOY
        % {
            "user_id": user_id,
            "organization_id": organization_id,
        }
    )


