"""Run as ``python scripts/load_polls.py`` — imports its sibling module directly."""

from seed_data import QUESTIONS


def load():
    return list(QUESTIONS)
