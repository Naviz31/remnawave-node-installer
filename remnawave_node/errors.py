class InstallerError(Exception):
    """Expected, user-facing failure."""

    def __init__(self, message: str, *, stage: str = "general", hint: str = ""):
        super().__init__(message)
        self.stage = stage
        self.hint = hint


class PreflightError(InstallerError):
    """A safety check failed before mutation."""


class ExternalConfigWait(InstallerError):
    """Installation is complete but panel configuration is not present yet."""
