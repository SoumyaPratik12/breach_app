import base64
import hashlib
import hmac
import os


SALT_BYTES = 16
KEY_LENGTH = 32

# scrypt parameters
N = 2**14
R = 8
P = 1


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)

    derived_key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=N,
        r=R,
        p=P,
        dklen=KEY_LENGTH,
    )

    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    key_b64 = base64.urlsafe_b64encode(derived_key).decode("ascii")

    return f"scrypt${N}${R}${P}${salt_b64}${key_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt_b64, key_b64 = stored_hash.split("$")

        if algorithm != "scrypt":
            return False

        salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected_key = base64.urlsafe_b64decode(key_b64.encode("ascii"))

        actual_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected_key),
        )

        return hmac.compare_digest(actual_key, expected_key)

    except (ValueError, TypeError):
        return False
