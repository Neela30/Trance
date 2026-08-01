"""Custom exceptions used across TRANCE core and modules."""


class TranceError(Exception):
    """Base exception for all TRANCE errors."""


class AcquisitionError(TranceError):
    """Raised when evidence acquisition fails."""


class ParsingError(TranceError):
    """Raised when an artifact cannot be parsed."""


class IntegrityError(TranceError):
    """Raised when a hash verification fails."""
