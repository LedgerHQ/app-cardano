# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Address check
"""

import pytest
import base58
import bech32m.codecs as bech32

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.backend.interface import RAPDU
from ragger.error import ExceptionRAPDU

from application_client.app_def import Errors, AddressType, Testnet
from application_client.command_sender import CommandSender
from application_client.command_builder import P1Type

from input_files.derive_address import DeriveAddressTestCase
from input_files.derive_address import byronTestCases, rejectTestCases
from input_files.derive_address import shelleyTestCasesNoConfirm, shelleyTestCasesWithConfirm


@staticmethod
def idfunc(val: DeriveAddressTestCase) -> str:
    return val.name


@pytest.mark.parametrize(
    "testCase",
    byronTestCases,
    ids=idfunc
)
def test_derive_byron_address(firmware: Firmware,
                              backend: BackendInterface,
                              navigator: Navigator,
                              scenario_navigator: NavigateWithScenario,
                              testCase: DeriveAddressTestCase) -> None:
    """Check Derive Byron Address Return"""
    if firmware == Firmware.NANOS:
        pytest.skip("Byron address derivation is not supported on Nano S")

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    if firmware.is_nano:
        nav_inst = NavInsID.BOTH_CLICK
        valid_instr = [NavInsID.BOTH_CLICK]
    else:
        nav_inst = NavInsID.SWIPE
        valid_instr = [NavInsID.USE_CASE_CHOICE_CONFIRM]

    # Send the APDU
    with client.derive_address_async(P1Type.P1_RETURN,
                                     testCase.addrType,
                                     testCase.netDesc,
                                     testCase.spendingValue,
                                     testCase.stakingValue):
        if firmware.is_nano:
            navigator.navigate_until_text(nav_inst, valid_instr, "Confirm")
        else:
            scenario_navigator.address_review_approve(do_comparison=False)

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS
    print(f" Address: {response.data.hex()}")

    assert testCase.result == base58.b58encode(response.data).decode()


@pytest.mark.parametrize(
    "testCase",
    byronTestCases,
    ids=idfunc
)
def test_derive_byron_show_address(firmware: Firmware,
                                   backend: BackendInterface,
                                   navigator: Navigator,
                                   scenario_navigator: NavigateWithScenario,
                                   testCase: DeriveAddressTestCase) -> None:
    """Check Derive Byron Address Show"""
    if firmware == Firmware.NANOS:
        pytest.skip("Byron address derivation is not supported on Nano S")

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    if firmware.is_nano:
        moves = []
        moves += [NavInsID.BOTH_CLICK] * 3
        moves += [NavInsID.RIGHT_CLICK]
        moves += [NavInsID.BOTH_CLICK] * 2

    # Send the APDU
    with client.derive_address_async(P1Type.P1_DISPLAY,
                                     testCase.addrType,
                                     testCase.netDesc,
                                     testCase.spendingValue,
                                     testCase.stakingValue):
        if firmware.is_nano:
            navigator.navigate(moves)
        else:
            scenario_navigator.address_review_approve(do_comparison=False)

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


@pytest.mark.parametrize(
    "testCase",
    shelleyTestCasesNoConfirm,
    ids=idfunc
)
def test_derive_shelley_address(backend: BackendInterface,
                                testCase: DeriveAddressTestCase) -> None:
    """Check Derive Shelley Address Return without confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Send the APDU
    response = client.derive_address(P1Type.P1_RETURN,
                                     testCase.addrType,
                                     testCase.netDesc,
                                     testCase.spendingValue,
                                     testCase.stakingValue)
    check_shelley_result(response, testCase)


@pytest.mark.parametrize(
    "testCase",
    shelleyTestCasesWithConfirm,
    ids=idfunc
)
def test_derive_shelley_address_confirm(firmware: Firmware,
                                        backend: BackendInterface,
                                        navigator: Navigator,
                                        scenario_navigator: NavigateWithScenario,
                                        testCase: DeriveAddressTestCase) -> None:
    """Check Derive Shelley Address Return with confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    if firmware.is_nano:
        nav_inst = NavInsID.BOTH_CLICK
        if firmware == Firmware.NANOS:
            valid_instr = [NavInsID.RIGHT_CLICK]
        else:
            valid_instr = [NavInsID.BOTH_CLICK]

    # Send the APDU
    with client.derive_address_async(P1Type.P1_RETURN,
                                     testCase.addrType,
                                     testCase.netDesc,
                                     testCase.spendingValue,
                                     testCase.stakingValue):
        if firmware.is_nano:
            if firmware != Firmware.NANOS and testCase.nano_nav_list:
                navigator.navigate(testCase.nano_nav_list)
            else:
                navigator.navigate_until_text(nav_inst, valid_instr, "Confirm")
        else:
            scenario_navigator.address_review_approve(do_comparison=False)

    # Check the status (Asynchronous)
    response = client.get_async_response()
    check_shelley_result(response, testCase)



def check_shelley_result(response: RAPDU, testCase: DeriveAddressTestCase) -> None:
    # Check the status (Asynchronous)
    assert response and response.status == Errors.SW_SUCCESS
    print(f" Address: {response.data.hex()}")

    data5bit = bech32.convertbits(response.data, 8, 5)
    if testCase.addrType in (AddressType.REWARD_KEY, AddressType.REWARD_SCRIPT):
        hrp = "stake"
    else:
        hrp = "addr"
    if testCase.netDesc == Testnet:
        hrp += "_test"
    assert testCase.result == bech32.bech32_encode(hrp, data5bit, bech32.Encoding.BECH32)


@pytest.mark.parametrize(
    "testCase",
    rejectTestCases,
    ids=idfunc
)
def test_reject_address(firmware: Firmware,
                        backend: BackendInterface,
                        testCase: DeriveAddressTestCase) -> None:
    """Check Derive Reject Address Return"""
    if firmware == Firmware.NANOS:
        pytest.skip("Byron address derivation is not supported on Nano S")

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as err:
        # Send the APDU
        client.derive_address(P1Type.P1_RETURN,
                              testCase.addrType,
                              testCase.netDesc,
                              testCase.spendingValue,
                              testCase.stakingValue)
    assert err.value.status == Errors.SW_REJECTED_BY_POLICY
