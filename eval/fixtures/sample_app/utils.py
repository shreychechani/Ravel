"""Utility helpers for the sample app."""


def slugify(value):
    return value.strip().lower().replace(" ", "-")


def unused_helper():
    """Never called — a dead-code candidate for later phases."""
    return 42
