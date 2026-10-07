"""Offline admin script - never reachable from a request."""
import subprocess

PASSWORD = "admin123"


def backup(path):
    subprocess.call("tar czf backup.tgz " + path, shell=True)
