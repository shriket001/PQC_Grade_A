"""File-sharing-domain errors (US4).

Mirrors `messaging_errors.py`'s shape: each carries an HTTP status +
`error_code`, mapped to the shared `{error_code, message}` response shape
(FR-022) by the composition root (main.py).
"""


class FileError(Exception):
    """Base for all file-sharing-domain errors raised by FileService."""

    status_code: int = 400
    error_code: str = "file_error"

    def __init__(self, message: str = "") -> None:
        self.message = message or self.error_code
        super().__init__(self.message)


class FileTooLargeError(FileError):
    status_code = 413
    error_code = "file_too_large"


class FileSizeMismatchError(FileError):
    # The actual streamed byte count didn't match the declared size — reject
    # rather than trust the client's declaration (FR-039).
    status_code = 400
    error_code = "file_size_mismatch"


class FileTypeNotAllowedError(FileError):
    status_code = 400
    error_code = "file_type_not_allowed"


class FileNotFoundError(FileError):
    status_code = 404
    error_code = "file_not_found"


class FileNotReadyError(FileError):
    # Upload never completed (still pending) or failed — never addressable
    # (FR-040).
    status_code = 404
    error_code = "file_not_ready"


class FileUploadFailedError(FileError):
    status_code = 502
    error_code = "file_upload_failed"
