class SbomFixerError(Exception):
    """Base class for errors that end a run with a clear message."""


class DetectError(SbomFixerError):
    """The input is not an SBOM format this tool can process."""


class SchemaNotFoundError(SbomFixerError):
    """No vendored schema exists for the requested spec and version."""


class ProfileError(SbomFixerError):
    """The profile file is missing, malformed or uses unknown keys."""
