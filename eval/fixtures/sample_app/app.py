"""A tiny FastAPI app used as a real parsing/graph fixture."""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .services import create_user, get_user

app = FastAPI()


class UserIn(BaseModel):
    """Request body — a third-party base class."""

    name: str


class UserNotFound(HTTPException):
    """Raised when a lookup misses."""


@app.get("/users/{user_id}")
def read_user(user_id: int):
    """Public endpoint — untrusted entry point."""
    return get_user(user_id)


@app.post("/users")
def add_user(user: UserIn):
    return create_user(user.name)
