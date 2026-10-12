import pytest


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


def test_create_identifier_rejects_malformed_email(client):
    headers = register_and_authenticate(
        client, "invalid-email-test@example.com"
    )
    response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": "email",
            "value": "not-an-email",
        },
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "phone",
    [
        "",
        "abc",
        "12345",
        "++123456789",
        "+1 (415) 555-2671 ext 2",
    ],
)
def test_create_identifier_rejects_invalid_phone(client, phone):
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


@pytest.mark.parametrize(
    ("phone", "masked_phone"),
    [
        ("+91 98765 43210", "+••••••3210"),
        ("+1 (415) 555-2671", "+••••••2671"),
        ("9876543210", "••••••3210"),
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
