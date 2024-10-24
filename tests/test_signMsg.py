# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Sign Message check
"""

import pytest
from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.app_def import Errors
from application_client.command_sender import CommandSender

from input_files.signMsg import signMsgTestCases, SignMsgTestCase, SignedMessageData

from utils import pop_sized_buf_from_buffer, pop_size_prefixed_buf_from_buf

from utils import idTestFunc


@pytest.mark.parametrize(
    "testCase",
    signMsgTestCases,
    ids=idTestFunc
)
def test_sign_message(firmware: Firmware,
                      backend: BackendInterface,
                      navigator: Navigator,
                      scenario_navigator: NavigateWithScenario,
                      testCase: SignMsgTestCase) -> None:
    """Check Sign Message"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    if firmware == Firmware.NANOS:
        moves = {
            "init": [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
            "chunk": [NavInsID.BOTH_CLICK],
            "confirm": [NavInsID.BOTH_CLICK] + [NavInsID.RIGHT_CLICK]
        }
        if testCase.msgData.messageHex:
            moves["chunk"] += [NavInsID.BOTH_CLICK]

    # Send the INIT APDU
    with client.sign_msg_init(testCase):
        if firmware.is_nano:
            if firmware == Firmware.NANOS:
                navigator.navigate(moves["init"])
            else:
                navigator.navigate(testCase.nav.init)
        else:
            navigator.navigate([NavInsID.SWIPE_CENTER_TO_LEFT])
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Send the CHUNK APDUs
    with client.sign_msg_chunk(testCase):
        if firmware.is_nano:
            if firmware == Firmware.NANOS:
                navigator.navigate(moves["chunk"])
            else:
                navigator.navigate(testCase.nav.chunk)
        else:
            navigator.navigate([NavInsID.TAPPABLE_CENTER_TAP])
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Send the CONFIRM APDUs
    with client.sign_msg_confirm():
        if firmware.is_nano:
            if firmware == Firmware.NANOS:
                navigator.navigate(moves["confirm"])
            else:
                navigator.navigate(testCase.nav.confirm)
        else:
            scenario_navigator.address_review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Check the response
    _check_result(testCase.expected, response.data)


def _check_result(expected: SignedMessageData, data: bytes):
    """Check the response, containing
    - ED25519 signature (64 bytes)
    - Public key (32 bytes)
    - Address field size (4 bytes)
    - Address field (Up to 128 bytes)
    """

    ED25519_SIGNATURE_LENGTH = 64
    PUBLIC_KEY_LENGTH = 32
    MAX_ADDRESS_SIZE = 128
    # Check the response length
    assert len(data) <= ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4 + MAX_ADDRESS_SIZE
    # Check the signature
    buffer = data
    buffer, signature = pop_sized_buf_from_buffer(buffer, ED25519_SIGNATURE_LENGTH)
    assert signature.hex() == expected.signatureHex
    # Check the public key
    buffer, signingPublicKey = pop_sized_buf_from_buffer(buffer, PUBLIC_KEY_LENGTH)
    assert signingPublicKey.hex() == expected.signingPublicKeyHex
    # Check the address field
    buffer, _, addressField = pop_size_prefixed_buf_from_buf(buffer, 4)
    assert addressField.hex() == expected.addressFieldHex
