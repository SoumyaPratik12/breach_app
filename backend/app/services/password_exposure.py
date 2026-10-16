import hashlib

import httpx

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
REQUEST_TIMEOUT_SECONDS = 5.0


class PasswordExposureProviderError(Exception):
    """Safe, generic error for password-exposure provider failures."""


def check_password_exposure(password: str) -> int:
    """
    Return the number of times a password appears in the HIBP dataset.

    Only the first five hexadecimal characters of the SHA-1 hash are sent.
    The password and full hash are never transmitted.
    """
    password_hash = hashlib.sha1(
        password.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest().upper()

    prefix = password_hash[:5]
    suffix = password_hash[5:]

    try:
        response = httpx.get(
            f"{HIBP_RANGE_URL}{prefix}",
            headers={
                "Add-Padding": "true",
                "User-Agent": "DigitalFootprintExposureScanner",
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPError:
        raise PasswordExposureProviderError(
            "Password exposure service is temporarily unavailable"
        ) from None

    for line in response.text.splitlines():
        try:
            returned_suffix, count_text = line.strip().split(":", 1)
            count = int(count_text)
        except (ValueError, AttributeError):
            raise PasswordExposureProviderError(
                "Password exposure service returned an invalid response"
            ) from None

        if count < 0:
            raise PasswordExposureProviderError(
                "Password exposure service returned an invalid response"
            )

        if returned_suffix.upper() == suffix:
            return count

    return 0