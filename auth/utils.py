"""Collection of utils."""
import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from .models import UserModel
from .settings import PASSWORD_CONTEXT, SETTINGS


def make_password_hash(*, password: str) -> str:
    """Turn a plain-text password into a hash for database storage.

    Args:
        password: plain text

    Example:
        >>> from auth import utils
        >>> hashed_password = utils.make_password_hash(password="raw password")
        >>> len(hashed_password) > 0
        True
        >>> type(hashed_password) == str
        True

    Returns:
        Hash string
    """
    return PASSWORD_CONTEXT.hash(password)


def verify_password(*, plain_password: str, hashed_password: str) -> bool:
    """Verify plain-text password.

    Args:
        plain_password: plain text
        hashed_password: hashed string

    Example:
        >>> from auth import utils
        >>> hashed_pass = utils.make_password_hash(password="raw password")
        >>> utils.verify_password(plain_password="raw password", hashed_password=hashed_pass) # noqa: B950
        True

    Returns:
        bool
    """
    return PASSWORD_CONTEXT.verify(plain_password, hashed_password)


def salted_hmac(
    *, key_salt: str, value: str, secret: Optional[str] = None, algorithm: str = "sha1"
) -> hmac.HMAC:
    """Generate a hmac salted.

    Return the HMAC of 'value', using a key generated from key_salt and a
    secret (which defaults to settings.SECRET_KEY). Default algorithm is SHA1,
    but any algorithm name supported by hashlib can be passed.
    A different key_salt should be passed in for every application of HMAC.

    Args:
        key_salt: A salt to be used when hashing the value.
        value: The message or the main object of the hash.
        secret: The secret key for the hash.
        algorithm: The hashing algorithm to use.

    Returns:
        HMAC instance.

    Raises:
        ValueError: When the algorithm is not valid hash algorithm.
    """
    if secret is None:
        secret = SETTINGS.authjwt_secret_key

    key_salt = key_salt.encode()
    secret = secret.encode()
    try:
        hasher = getattr(hashlib, algorithm)
    except AttributeError as e:
        raise ValueError(
            f"{algorithm} is not an algorithm accepted by the hashlib module."
        ) from e
    # We need to generate a derived key from our base key.  We can do this by
    # passing the key_salt and our base key through a pseudo-random function.
    key = hasher(key_salt + secret).digest()
    # If len(key_salt + secret) > block size of the hash algorithm, the above
    # line is redundant and could be replaced by key = key_salt + secret, since
    # the hmac module does the same thing for keys longer than the block size.
    # However, we need to ensure that we *always* do this.
    return hmac.new(key, msg=value.encode(), digestmod=hasher)


def constant_time_compare(val1: str, val2: str) -> bool:
    """Return True if the two strings are equal, False otherwise."""
    return secrets.compare_digest(val1.encode(), val2.encode())


def base36_to_int(value: str) -> int:
    """Convert a base 36 string to an int.

    Args:
        value: A base 36.

    Returns:
        The converted int from base36.

    Raises:
        ValueError: If the input won't fit into an int.
    """
    # To prevent overconsumption of server resources, reject any
    # base36 string that is longer than 13 base36 digits (13 digits
    # is sufficient to base36-encode any 64-bit integer)
    if len(value) > 13:
        raise ValueError("Base36 input too large")
    return int(value, 36)


def int_to_base36(value: int) -> str:
    """Convert an integer to a base36 string."""
    char_set = "0123456789abcdefghijklmnopqrstuvwxyz"

    if value < 0:
        raise ValueError("Negative base36 conversion input.")

    if value < 36:
        return char_set[value]

    b36 = ""

    while value != 0:
        value, n = divmod(value, 36)
        b36 = char_set[n] + b36
    return b36


class TokenGenerator(BaseModel):
    """Generate and check tokens for the password reset and email verification."""

    key_salt: str = "auth.TokenGenerator"
    algorithm: str = "sha256"
    _secret: Optional[str] = None

    def _get_secret(self: "TokenGenerator") -> str:
        """Getting the secret key either from the _secret or authjwt_secret_key."""
        return self._secret or SETTINGS.authjwt_secret_key

    def make_token(self: "TokenGenerator", user: UserModel) -> str:
        """Return a token that can be used once to do a password reset for the given user."""
        return self._make_token_with_timestamp(user, self._num_seconds(self._now()))

    def check_token(
        self: "TokenGenerator", user: UserModel, token: str
    ) -> bool:
        """Check that a password reset token is correct for a given user."""
        if not (user and token):
            return False
        # Parse the token
        try:
            ts_b36, _ = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False

        # Check the timestamp is within limit.
        if (self._num_seconds(self._now()) - ts) > SETTINGS.PASSWORD_RESET_TIMEOUT:
            return False

        return True

    def _make_token_with_timestamp(
        self: "TokenGenerator", user: UserModel, timestamp: int
    ) -> str:
        # timestamp is number of seconds since 2001-1-1. Converted to base 36,
        # this gives us a 6 digit string until about 2069.
        ts_b36 = int_to_base36(timestamp)
        hash_string = salted_hmac(
            key_salt=self.key_salt,
            value=self._make_hash_value(user, timestamp),
            secret=self._get_secret(),
            algorithm=self.algorithm,
        ).hexdigest()[
            ::2
        ]  # Limit to shorten the URL.
        return f"{ts_b36}-{hash_string}"

    def _make_hash_value(
        self: "TokenGenerator", user: UserModel, timestamp: int
    ) -> str:
        """Hash the user's primary key, email.
        Hash the user's primary key, email (if available), and some user state
        that's sure to change after a password reset to produce a token that is
        invalidated when it's used:
        1. The password field will change upon a password reset (even if the
           same password is chosen, due to password salting).
        2. The last_login field will usually be updated very shortly after
           a password reset.
        Failing those things, settings.PASSWORD_RESET_TIMEOUT eventually
        invalidates the token.
        Running this data through salted_hmac() prevents password cracking
        attempts using the reset token, provided the secret isn't compromised.
        """
        # Truncate microseconds so that tokens are consistent even if the
        # database doesn't support microseconds.
        login_timestamp = (
            ""
            if user.last_login is None
            else user.last_login.replace(microsecond=0, tzinfo=None)
        )
        return f"{user.id}{user.password}{user.is_email_verified}{login_timestamp}{timestamp}{user.email}"

    @staticmethod
    def _num_seconds(dt: datetime) -> int:
        return int((dt - datetime(2001, 1, 1)).total_seconds())

    @staticmethod
    def _now() -> datetime:
        # Used for mocking in tests
        return datetime.now()


default_token_generator = TokenGenerator()
