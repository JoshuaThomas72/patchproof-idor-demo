from scanner.context import prepare_context, strip_python_comments, verify_citations

SRC = '''\
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()
TOKENS = {"alice-token": "alice"}  # demo only


def signed_in_user(authorization: str | None = Header(default=None)):
    user = TOKENS.get(authorization or "")
    if not user:
        raise HTTPException(status_code=401)
    return user


@app.get("/documents/{document_id}")
def get_document(document_id: str, authorization: str | None = Header(default=None)):
    # INTENTIONAL IDOR: missing document-owner authorization check.
    user = signed_in_user(authorization)
    note = "# not a comment"
    return {"user": user, "note": note}
'''


def test_comments_are_removed_but_line_numbers_are_kept():
    stripped, ok = strip_python_comments(SRC)
    assert ok
    assert "INTENTIONAL" not in stripped and "demo only" not in stripped
    assert '"# not a comment"' in stripped
    assert len(stripped.splitlines()) == len(SRC.splitlines())


def test_function_context_includes_auth_helper_and_constants():
    line = next(i for i, t in enumerate(SRC.splitlines(), 1) if "user = signed_in_user" in t)
    prepared = prepare_context(SRC, line, ".py")
    meta, text = prepared["meta"], prepared["text"]
    assert meta["function"] == "get_document"
    assert meta["helpers"] == ["signed_in_user"]
    assert meta["constants"] == ["TOKENS"]
    assert meta["comments_stripped"] is True
    assert "raise HTTPException(status_code=401)" in text
    assert "INTENTIONAL" not in text


def test_non_python_falls_back_to_a_numbered_window():
    prepared = prepare_context("a\nb\nc\n", 2, ".tsx")
    assert prepared["meta"]["fallback"] == "line_window"
    assert prepared["text"].splitlines()[0].startswith("1: ")


def test_citations_must_quote_the_cited_line():
    context = "10: user = signed_in_user(authorization)\n11: return document"
    quote = "signed_in_user(authorization)"
    assert verify_citations(context, [{"line": 10, "quote": quote}])["verified"] == 1
    assert verify_citations(context, [{"line": 11, "quote": quote}])["verified"] == 1  # slack of 1
    assert verify_citations(context, [{"line": 10, "quote": "if document['owner'] != user"}])["verified"] == 0
    assert verify_citations(context, [{"line": 10, "quote": "user"}])["verified"] == 0  # too short
    assert verify_citations(context, "not a list")["total"] == 0