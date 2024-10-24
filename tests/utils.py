# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests utility functions
"""
from pathlib import Path
from typing import List, Tuple, Union
import re

from input_files.derive_address import DeriveAddressTestCase
from input_files.pubkey import PubKeyTestCase
from input_files.cvote import CVoteTestCase
from input_files.signOpCert import OpCertTestCase
from input_files.signMsg import SignMsgTestCase


ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


def idTestFunc(testCase: Union[DeriveAddressTestCase, PubKeyTestCase, CVoteTestCase, OpCertTestCase, SignMsgTestCase]) -> str:
    """Retrieve the test case name for friendly display

    Args:
        testCase (xxxTestCase): Targeted test case

    Returns:
        Test case name
    """
    return testCase.name


def pop_sized_buf_from_buffer(buffer:bytes, size:int) -> Tuple[bytes, bytes]:
    """Extract a buffer of a given size from a buffer

    Args:
        buffer (bytes): Source buffer
        size (int): Size of the buffer to extract

    Returns:
        Tuple of:
            - The remaining buffer
            - The extracted buffer
    """
    return buffer[size:], buffer[0:size]


def pop_size_prefixed_buf_from_buf(buffer:bytes, lenSize:int) -> Tuple[bytes, int, bytes]:
    """Extract a buffer prefixed with its size from a buffer

    Args:
        buffer (bytes): Source buffer
        lenSize (int): Size of the length prefix

    Returns:
        Tuple of:
            - The remaining buffer
            - The extracted data length
            - The extracted buffer
    """
    data_len = int.from_bytes(buffer[0:lenSize], "big")
    return buffer[lenSize+data_len:], data_len, buffer[lenSize:data_len+lenSize]


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def verify_name(name: str) -> None:
    """Verify the app name, based on defines in Makefile

    Args:
        name (str): Name to be checked
    """

    name_str = ""
    lines = _read_makefile()
    name_re = re.compile(r"^APPNAME\s*=\s*\"?(?P<val>[ \ta-zA-Z0-9_]+)\"?", re.I)
    for line in lines:
        info = name_re.match(line)
        if info:
            dinfo = info.groupdict()
            name_str = dinfo["val"]
            break
    assert name == name_str


def _read_makefile() -> List[str]:
    """Read lines from the parent Makefile"""

    parent = Path(ROOT_SCREENSHOT_PATH).parent.resolve()
    makefile = f"{parent}/Makefile"
    with open(makefile, "r", encoding="utf-8") as f_p:
        lines = f_p.readlines()

    return lines
