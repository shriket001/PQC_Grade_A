"""FileStorage — object-storage repository abstraction over an S3-compatible
backend (MinIO in dev/docker, per `docker/docker-compose.yml`).

Holds only ciphertext produced client-side (FR-051/SC-002) — this module never
sees plaintext and performs no encryption/decryption itself. `boto3` is
synchronous, so calls are offloaded to a thread via `asyncio.to_thread` to
avoid blocking the event loop.
"""

import asyncio
from typing import IO

import boto3
from botocore.client import Config


class FileStorage:
    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        access_key: str,
        secret_key: str,
    ) -> None:
        self._bucket = bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version="s3v4"),
        )

    async def put_object(self, key: str, fileobj: IO[bytes]) -> None:
        await asyncio.to_thread(self._client.upload_fileobj, fileobj, self._bucket, key)

    async def get_object(self, key: str) -> bytes:
        def _get() -> bytes:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            return response["Body"].read()  # type: ignore[no-any-return]

        return await asyncio.to_thread(_get)

    async def delete_object(self, key: str) -> None:
        await asyncio.to_thread(self._client.delete_object, Bucket=self._bucket, Key=key)
