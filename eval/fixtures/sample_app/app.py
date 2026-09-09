"""A tiny FastAPI app used as a real parsing/graph fixture."""

from fastapi import FastAPI

from .services import create_user, get_user

app = FastAPI()


@app.get("/users/{user_id}")
def read_user(user_id: int):
    """Public endpoint — untrusted entry point."""
    return get_user(user_id)


@app.post("/users")
def add_user(name: str):
    return create_user(name)
