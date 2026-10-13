#
# auto-pts - The Bluetooth PTS Automation Framework
#
# Copyright (c) 2026 The BleHub Contributors.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#

"""BleHub-owned BTP control-plane extensions.

This module is deliberately limited to read-only fixture identity. It does not
flash, reset, provision, or start a Peripheral. The host fixture controller
owns those lifecycle operations.
"""

from dataclasses import dataclass
from uuid import UUID

from autopts.pybtp import defs
from autopts.pybtp.btp.btp import btp_hdr_check
from autopts.pybtp.btp.btp import get_iut_method as get_iut
from autopts.pybtp.types import BTPError

BTP_BLEHUB_CMD_READ_IMAGE_ATTESTATION = 0x01
BLEHUB_ATTESTATION_SCHEMA_VERSION = 1
BLEHUB_ATTESTATION_INDEX = defs.BTP_INDEX_NONE
BLEHUB_ATTESTATION_MAX_PAYLOAD = 1024
BLEHUB_ATTESTATION_FIELD_COUNT = 8
BLEHUB_ATTESTATION_TAGS = frozenset(range(1, BLEHUB_ATTESTATION_FIELD_COUNT + 1))
BLEHUB_ATTESTATION_SHA256_LENGTH = 32
BLEHUB_ATTESTATION_UUID_LENGTH = 16

_TAG_IMAGE_ID = 1
_TAG_IMAGE_VERSION = 2
_TAG_IMAGE_SHA256 = 3
_TAG_BOARD = 4
_TAG_PROFILE_ID = 5
_TAG_SERVICE_UUID = 6
_TAG_LOCAL_NAME = 7
_TAG_CAPABILITIES = 8


class BleHubAttestationError(BTPError):
    """Raised when the fixture identity response is not canonical."""


@dataclass(frozen=True)
class BleHubImageAttestation:
    """Identity returned by the installed fixture image control plane."""

    image_id: str
    image_version: str
    image_sha256: str
    board: str
    profile_id: str
    service_uuid: str
    local_name: str
    capabilities: tuple[str, ...]

    def as_document(self) -> dict[str, object]:
        """Return the stable JSON representation used by host evidence."""
        return {
            "schema_version": BLEHUB_ATTESTATION_SCHEMA_VERSION,
            "image_id": self.image_id,
            "image_version": self.image_version,
            "image_sha256": self.image_sha256,
            "board": self.board,
            "profile_id": self.profile_id,
            "service_uuid": self.service_uuid,
            "local_name": self.local_name,
            "capabilities": list(self.capabilities),
        }


def _text(value: bytes, field: str) -> str:
    if not value or b"\x00" in value:
        raise BleHubAttestationError(f"{field} must be non-empty UTF-8 without NUL")
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BleHubAttestationError(f"{field} is not valid UTF-8") from error
    if not decoded.strip():
        raise BleHubAttestationError(f"{field} must not be blank")
    return decoded


def _capabilities(value: bytes) -> tuple[str, ...]:
    if not value:
        raise BleHubAttestationError("capabilities payload is empty")
    count = value[0]
    if count == 0:
        raise BleHubAttestationError("capabilities must not be empty")
    offset = 1
    decoded: list[str] = []
    for _ in range(count):
        if offset >= len(value):
            raise BleHubAttestationError("capabilities payload is truncated")
        length = value[offset]
        offset += 1
        end = offset + length
        if length == 0 or end > len(value):
            raise BleHubAttestationError("capability has an invalid length")
        decoded.append(_text(value[offset:end], "capability"))
        offset = end
    if offset != len(value) or len(set(decoded)) != len(decoded):
        raise BleHubAttestationError("capabilities payload has trailing or duplicate data")
    return tuple(decoded)


def decode_image_attestation(payload: bytes) -> BleHubImageAttestation:
    """Decode one strict BleHub vendor response without accepting unknown fields."""
    if len(payload) > BLEHUB_ATTESTATION_MAX_PAYLOAD:
        raise BleHubAttestationError("attestation payload exceeds BTP limit")
    if len(payload) < 2:
        raise BleHubAttestationError("attestation payload is truncated")
    if payload[0] != BLEHUB_ATTESTATION_SCHEMA_VERSION:
        raise BleHubAttestationError(f"unsupported attestation schema: {payload[0]}")
    field_count = payload[1]
    if field_count != BLEHUB_ATTESTATION_FIELD_COUNT:
        raise BleHubAttestationError("attestation field count is not exact")

    offset = 2
    fields: dict[int, bytes] = {}
    for _ in range(field_count):
        if offset + 3 > len(payload):
            raise BleHubAttestationError("attestation field header is truncated")
        tag = payload[offset]
        length = int.from_bytes(payload[offset + 1 : offset + 3], "little")
        offset += 3
        end = offset + length
        if tag not in BLEHUB_ATTESTATION_TAGS or tag in fields:
            raise BleHubAttestationError(f"unknown or duplicate attestation tag: {tag}")
        if end > len(payload):
            raise BleHubAttestationError("attestation field is truncated")
        fields[tag] = payload[offset:end]
        offset = end
    if offset != len(payload) or set(fields) != BLEHUB_ATTESTATION_TAGS:
        raise BleHubAttestationError("attestation payload has trailing or missing fields")

    image_sha256 = fields[_TAG_IMAGE_SHA256]
    service_uuid = fields[_TAG_SERVICE_UUID]
    if len(image_sha256) != BLEHUB_ATTESTATION_SHA256_LENGTH:
        raise BleHubAttestationError("image SHA-256 must contain 32 raw bytes")
    if len(service_uuid) != BLEHUB_ATTESTATION_UUID_LENGTH:
        raise BleHubAttestationError("service UUID must contain 16 raw bytes")
    return BleHubImageAttestation(
        image_id=_text(fields[_TAG_IMAGE_ID], "image_id"),
        image_version=_text(fields[_TAG_IMAGE_VERSION], "image_version"),
        image_sha256=image_sha256.hex(),
        board=_text(fields[_TAG_BOARD], "board"),
        profile_id=_text(fields[_TAG_PROFILE_ID], "profile_id"),
        service_uuid=str(UUID(bytes=service_uuid)),
        local_name=_text(fields[_TAG_LOCAL_NAME], "local_name"),
        capabilities=_capabilities(fields[_TAG_CAPABILITIES]),
    )


def blehub_read_image_attestation(timeout: float = 20.0) -> BleHubImageAttestation:
    """Read installed image identity through the BTP control plane only."""
    iutctl = get_iut()
    iutctl.btp_socket.send(
        defs.BTP_SERVICE_ID_VENDOR,
        BTP_BLEHUB_CMD_READ_IMAGE_ATTESTATION,
        BLEHUB_ATTESTATION_INDEX,
        data=b"",
    )
    tuple_hdr, tuple_data = iutctl.btp_socket.read(timeout)
    btp_hdr_check(
        tuple_hdr,
        defs.BTP_SERVICE_ID_VENDOR,
        BTP_BLEHUB_CMD_READ_IMAGE_ATTESTATION,
    )
    payload = tuple_data[0] if isinstance(tuple_data, tuple) else tuple_data
    if not isinstance(payload, bytes):
        raise BleHubAttestationError("attestation response is not bytes")
    return decode_image_attestation(payload)
