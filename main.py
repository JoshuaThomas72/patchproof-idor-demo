from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="PatchProof IDOR Demo")

# Demo-only identities and tokens. These are not real credentials.
TOKENS = {"alice-token": "alice", "bob-token": "bob"}
DOCUMENTS = {
    "doc-101": {
        "owner": "alice",
        "filename": "demo-secret.txt",
        "content": "Fake demo file: Alice's project notes.",
    }
}


class LoginRequest(BaseModel):
    username: str


@app.post("/login")
def login(request: LoginRequest):
    if request.username not in {"alice", "bob"}:
        raise HTTPException(status_code=401, detail="Unknown demo user")
    return {"access_token": f"{request.username}-token"}


def signed_in_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Sign-in required")

    token = authorization.removeprefix("Bearer ").strip()
    user = TOKENS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid demo token")
    return user


@app.get("/documents/{document_id}")
def get_document(
    document_id: str,
    user: str = Header(default=""),
    authorization: str | None = Header(default=None),
):
    # Validate the demo token; ownership is intentionally not checked yet.
    user = signed_in_user(authorization)

    document = DOCUMENTS.get(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    if document["owner"] != user:
        raise HTTPException(status_code=404, detail="Document not found")    
    # INTENTIONAL IDOR: missing document-owner authorization check.
    return {
        "requested_by": user,
        "owner": document["owner"],
        "filename": document["filename"],
        "content": document["content"],
    }