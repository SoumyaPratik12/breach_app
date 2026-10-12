import pytest

from app.models import Identifier


def register_and_authenticate(client, email):
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("email", ["not-an-email", "sammy@"])
def test_create_identifier_rejects_malformed_email(
    client,
    db_session,
    email,
):
    headers = register_and_authenticate(
        client, "invalid-email-test@example.com"
    )
    response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": "email",
            "value": email,
        },
    )

    assert response.status_code == 422
    assert db_session.query(Identifier).count() == 0


@pytest.mark.parametrize(
    "phone",
    [
        "",
        "abc",
        "123456",
        "12345",
        "1234567890123456",
        "++123456789",
        "+1-415.555-2671",
        "+1 (415) 555-2671 ext 2",
        "+91 ABCDE12345",
        "\t1234567",
        "١٢٣٤٥٦٧",
    ],
)
def test_create_identifier_rejects_invalid_phone(
    client,
    db_session,
    phone,
):
    headers = register_and_authenticate(
        client, "invalid-phone-test@example.com"
    )
    response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": "phone",
            "value": phone,
        },
    )

    assert response.status_code == 422
    assert db_session.query(Identifier).count() == 0


@pytest.mark.parametrize(
    ("phone", "masked_phone"),
    [
        ("1234567", "••••••4567"),
        ("+91 98765 43210", "+••••••3210"),
        ("+1 (415) 555-2671", "+••••••2671"),
        ("9876543210", "••••••3210"),
        ("123456789012345", "••••••2345"),
    ],
)
def test_create_identifier_accepts_and_masks_valid_phone(
    client,
    phone,
    masked_phone,
):
    headers = register_and_authenticate(
        client, "valid-phone-test@example.com"
    )
    response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": "phone",
            "value": phone,
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["display_value"] == masked_phone
    assert phone not in response.text


@pytest.mark.parametrize(
    ("identifier_type", "value", "masked_value"),
    [
        ("username", "Alice! Example", "A••••"),
        ("name", "Mary-Jane", "M••••"),
    ],
)
def test_username_and_name_validation_remains_unchanged(
    client,
    identifier_type,
    value,
    masked_value,
):
    headers = register_and_authenticate(
        client, "unchanged-validation@example.com"
    )
    response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": identifier_type,
            "value": value,
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["display_value"] == masked_value
