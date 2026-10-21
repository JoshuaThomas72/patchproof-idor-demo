
import pytest
from fastapi.testclient import TestClient

import main
import main_vulnerable


@pytest.mark.parametrize(
    "module, alice_can_read_bobs_document",
    [
        (main_vulnerable, True),  # Vulnerability reproduction
        (main, False),            # Fixed version
    ],
)
def test_document_ownership(module, alice_can_read_bobs_document):
    client = TestClient(module.app)

    # The current demo data contains Alice's document.
    response = client.get(
        "/documents/doc-101",
        headers={"Authorization": "Bearer bob-token"},
    )

    if alice_can_read_bobs_document:
        assert response.status_code == 200
        assert response.json()["owner"] == "alice"
    else:
        assert response.status_code == 404


def test_owner_can_read_own_document():
    client = TestClient(main.app)

    response = client.get(
        "/documents/doc-101",
        headers={"Authorization": "Bearer alice-token"},
    )

    assert response.status_code == 200
    assert response.json()["owner"] == "alice"
