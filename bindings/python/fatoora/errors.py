class FatooraError(RuntimeError):
    """Base error for the fatoora Python bindings."""


class FfiError(FatooraError):
    """Error raised when the FFI layer reports a failure."""
