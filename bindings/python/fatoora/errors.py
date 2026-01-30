from __future__ import annotations

from enum import IntEnum


class FatooraError(RuntimeError):
    """Base error for the fatoora Python bindings."""


class FfiErrorKind(IntEnum):
    INVALID_INPUT = 1
    VALIDATION = 2
    PARSE = 3
    XML = 4
    CRYPTO = 5
    IO = 6
    NETWORK = 7
    UNAUTHORIZED = 8
    INTERNAL = 9
    API = 10


class FfiError(FatooraError):
    """Error raised when the FFI layer reports a failure."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.kind = FfiErrorKind(code) if code in FfiErrorKind._value2member_map_ else None


class InvalidInputError(FfiError):
    pass


class ValidationError(FfiError):
    pass


class ParseError(FfiError):
    pass


class XmlError(FfiError):
    pass


class CryptoError(FfiError):
    pass


class IoError(FfiError):
    pass


class NetworkError(FfiError):
    pass


class UnauthorizedError(FfiError):
    pass


class InternalError(FfiError):
    pass


class ApiError(FfiError):
    pass


def error_class_for_code(code: int | None) -> type[FfiError]:
    mapping = {
        FfiErrorKind.INVALID_INPUT: InvalidInputError,
        FfiErrorKind.VALIDATION: ValidationError,
        FfiErrorKind.PARSE: ParseError,
        FfiErrorKind.XML: XmlError,
        FfiErrorKind.CRYPTO: CryptoError,
        FfiErrorKind.IO: IoError,
        FfiErrorKind.NETWORK: NetworkError,
        FfiErrorKind.UNAUTHORIZED: UnauthorizedError,
        FfiErrorKind.INTERNAL: InternalError,
        FfiErrorKind.API: ApiError,
    }
    if code is None:
        return FfiError
    kind = FfiErrorKind(code) if code in FfiErrorKind._value2member_map_ else None
    return mapping.get(kind, FfiError)
