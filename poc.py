import httpx

BASE_URL = "http://127.0.0.1:8000"

with httpx.Client(base_url=BASE_URL, timeout=5) as client:
    alice = client.post("/login", json={"username": "alice"})
    bob = client.post("/login", json={"username": "bob"})
    alice.raise_for_status()
    bob.raise_for_status()

    print("Alice login: OK")
    print("Bob login:   OK")

    response = client.get(
        "/documents/doc-101",
        headers={"Authorization": f"Bearer {bob.json()['access_token']}"},
    )
    print(f"Bob requests Alice's document: HTTP {response.status_code}")

    if response.status_code == 200 and response.json().get("owner") == "alice":
        print("Returned file:", response.json()["filename"])
        print("\033[91mVULNERABLE: Bob downloaded Alice's file.\033[0m")
    elif response.status_code in (403, 404):
        print("BLOCKED: another user's file was denied.")
    else:
        print("Unexpected result:", response.text)