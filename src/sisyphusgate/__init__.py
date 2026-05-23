"""SisyphusGate - A modular honeypot system."""

try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("sisyphusgate")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"