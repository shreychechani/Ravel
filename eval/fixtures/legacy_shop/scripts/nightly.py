"""Nightly report job, run from cron — never reachable from a request."""
import locale


def locale_banner():
    language, encoding = locale.getdefaultlocale()
    return f"report locale: {language} ({encoding})"
