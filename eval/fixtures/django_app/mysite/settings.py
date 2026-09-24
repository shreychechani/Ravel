"""Minimal settings for the polls fixture (modelled on the Django tutorial)."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "fixture-only-not-a-secret"
DEBUG = True
ALLOWED_HOSTS: list[str] = []

INSTALLED_APPS = [
    "polls.apps.PollsConfig",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
]

ROOT_URLCONF = "mysite.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Per-machine overrides; local_settings.py is gitignored in real projects.
try:  # noqa: SIM105 — the real-world idiom, kept verbatim
    from .local_settings import *  # noqa: F403
except ImportError:
    pass
