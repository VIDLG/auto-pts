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

from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

import pytest

from autopts.pybtp import defs
from autopts.pybtp.btp.blehub import (
    BTP_BLEHUB_CMD_READ_IMAGE_ATTESTATION,
    BleHubAttestationError,
    BleHubImageAttestation,
    blehub_read_image_attestation,
    decode_image_attestation,
)


def _field(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + len(value).to_bytes(2, "little") + value


def _payload() -> bytes:
    first_capability = b"diagnostic-btp"
    second_capability = b"att-read-hold"
    capabilities = b"\x02" + bytes((len(first_capability),)) + first_capability
    capabilities += bytes((len(second_capability),)) + second_capability
    return b"\x01\x08" + b"".join(
        (
            _field(1, b"nrf-att-read-hold-v1"),
            _field(2, b"2026-10-13"),
            _field(3, bytes.fromhex("11" * 32)),
            _field(4, b"nrf52840dk/nrf52840"),
            _field(5, b"blehub-nrf52840-att-read-hold-v1"),
            _field(6, UUID("fd100000-0000-4000-8000-000000000000").bytes),
            _field(7, b"BleHubAttHoldDK"),
            _field(8, capabilities),
        )
    )


def test_decode_returns_canonical_identity_document() -> None:
    attestation = decode_image_attestation(_payload())

    assert isinstance(attestation, BleHubImageAttestation)
    assert attestation.image_sha256 == "11" * 32
    assert attestation.service_uuid == "fd100000-0000-4000-8000-000000000000"
    assert attestation.capabilities == ("diagnostic-btp", "att-read-hold")
    assert attestation.as_document()["schema_version"] == 1


def test_command_reads_blehub_vendor_opcode_without_core_service_registration() -> None:
    sent: list[tuple[tuple[object, ...], dict[str, object]]] = []
    socket = SimpleNamespace(
        sent=sent,
        send=lambda *args, **kwargs: sent.append((args, kwargs)),
        read=lambda _timeout: (
            SimpleNamespace(
                svc_id=defs.BTP_SERVICE_ID_VENDOR,
                op=BTP_BLEHUB_CMD_READ_IMAGE_ATTESTATION,
            ),
            (_payload(),),
        ),
    )
    iut = SimpleNamespace(btp_socket=socket)

    with patch("autopts.pybtp.btp.blehub.get_iut", return_value=iut):
        result = blehub_read_image_attestation(timeout=1.0)

    assert result.image_id == "nrf-att-read-hold-v1"
    assert sent == [
        (
            (
                defs.BTP_SERVICE_ID_VENDOR,
                BTP_BLEHUB_CMD_READ_IMAGE_ATTESTATION,
                defs.BTP_INDEX_NONE,
            ),
            {"data": b""},
        )
    ]


def test_unknown_duplicate_and_truncated_payloads_fail_closed() -> None:
    payload = bytearray(_payload())
    payload[2] = 0xFE
    with pytest.raises(BleHubAttestationError):
        decode_image_attestation(bytes(payload))

    duplicate = bytearray(_payload())
    duplicate[2] = 2
    duplicate[5] = 1
    with pytest.raises(BleHubAttestationError):
        decode_image_attestation(bytes(duplicate))

    with pytest.raises(BleHubAttestationError):
        decode_image_attestation(_payload()[:-1])
