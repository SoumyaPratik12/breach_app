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


def test_create_identifier_returns_masked_email(client, db_session):
    headers = register_and_authenticate(
        client, "mask-test@example.com"
    )
    response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": "email",
            "value": "sammy@example.com",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["display_value"] == "s•••••@example.com"
    assert response.json()["display_value"] != "sammy@example.com"
    stored_identifier = db_session.query(Identifier).one()
    assert stored_identifier.display_value.startswith("enc:v1:")


def test_list_identifiers_returns_masked_email(client):
    headers = register_and_authenticate(
        client, "mask-list@example.com"
    )
    create_response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": "email",
            "value": "sammy@example.com",
        },
    )
    assert create_response.status_code == 201, create_response.text

    response = client.get(
        "/identifiers",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["display_value"] == "s•••••@example.com"
    assert response.json()[0]["display_value"] != "sammy@example.com"


def test_create_identifier_returns_masked_phone(client):
    headers = register_and_authenticate(
        client, "mask-phone@example.com"
    )
    response = client.post(
        "/identifiers",
        headers=headers,
        json={
            "type": "phone",
            "value": "+919876543210",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["display_value"] == "+••••••3210"
    assert "+919876543210" not in response.text


def test_user_cannot_list_another_users_identifiers(client):
    owner_headers = register_and_authenticate(
        client, "vault-owner@example.com"
    )
    create_response = client.post(
        "/identifiers",
        headers=owner_headers,
        json={
            "type": "email",
            "value": "private-owner@example.com",
        },
    )
    assert create_response.status_code == 201, create_response.text

    other_headers = register_and_authenticate(
        client, "vault-other@example.com"
    )
    response = client.get("/identifiers", headers=other_headers)
    assert response.status_code == 200, response.text
    assert response.json() == []
    assert "private-owner@example.com" not in response.text
