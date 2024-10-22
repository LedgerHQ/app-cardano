# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for CIP36 check
"""

import pytest

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.app_def import Errors
from application_client.command_sender import CommandSender

from input_files.cvote import cvoteTestCases, CVoteTestCase

from utils import idTestFunc


@pytest.mark.parametrize(
    "testCase",
    cvoteTestCases,
    ids=idTestFunc
)
def test_cvote(firmware: Firmware,
               backend: BackendInterface,
               navigator: Navigator,
               scenario_navigator: NavigateWithScenario,
               testCase: CVoteTestCase) -> None:
    """Check CIP36 Vote"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    if firmware.is_nano:
        if firmware == Firmware.NANOS:
            moves_init = [NavInsID.RIGHT_CLICK]
            moves_init += [NavInsID.BOTH_CLICK] * 3
            moves_confirm = [NavInsID.RIGHT_CLICK]
            moves_witness = [NavInsID.BOTH_CLICK]
            moves_witness += [NavInsID.RIGHT_CLICK]
        else:
            moves_init = [NavInsID.BOTH_CLICK]
            moves_init += [NavInsID.RIGHT_CLICK]
            moves_init += [NavInsID.BOTH_CLICK] * 3
            moves_confirm = [NavInsID.BOTH_CLICK]
            moves_witness = [NavInsID.BOTH_CLICK] * 2
    else:
        moves_init = [NavInsID.SWIPE_CENTER_TO_LEFT]

    # Send the INIT APDU
    with client.sign_cip36_init(testCase):
        navigator.navigate(moves_init)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Send the CHUNK APDUs
    response = client.sign_cip36_chunk(testCase)
    # Check the status
    assert response and response.status == Errors.SW_SUCCESS

    # Send the CONFIRM APDUs
    with client.sign_cip36_confirm():
        if firmware.is_nano:
            navigator.navigate(moves_confirm)
        else:
            scenario_navigator.address_review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Check the response
    assert response.data.hex() == testCase.expected.dataHashHex

    # Send the WITNESS APDUs
    with client.sign_cip36_witness(testCase):
        if firmware.is_nano:
            navigator.navigate(moves_witness)
        else:
            scenario_navigator.review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Check the response
    assert response.data.hex() == testCase.expected.witnessSignatureHex
