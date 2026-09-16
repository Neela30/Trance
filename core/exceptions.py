"""Custom exceptions used across TRANCE core and modules."""


class TranceError(Exception):
    """Base exception for all TRANCE errors."""


class AcquisitionError(TranceError):
    """Raised when evidence acquisition fails."""


class ParsingError(TranceError):
    """Raised when an artifact cannot be parsed."""


class IntegrityError(TranceError):
    """Raised when a hash verification fails."""


class AnalysisError(TranceError):
    """Raised when a structural/tool-based analysis pass cannot run at all (the tool or
    its binary is missing, or the input it needs is unreadable) — as opposed to a single
    sub-check within that pass failing, which callers are expected to record and continue
    past rather than raise for."""
