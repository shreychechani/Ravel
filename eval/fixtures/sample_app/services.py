"""Service layer for the sample app."""

from .utils import slugify

_DB: dict[str, dict[str, str]] = {}


class UserService:
    """Holds the tiny in-memory user store."""

    def find(self, user_id):
        return _DB.get(str(user_id))


def get_user(user_id):
    return UserService().find(user_id)


def create_user(name):
    key = slugify(name)
    _DB[key] = {"name": name}
    return _DB[key]
