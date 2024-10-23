# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command sending part.
"""

from typing import Generator, Optional
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU

from input_files.derive_address import DeriveAddressTestCase
from input_files.pubkey import PubKeyTestCase
from input_files.cvote import CVoteTestCase
from input_files.signOpCert import OpCertTestCase

from application_client.command_builder import CommandBuilder, P1Type
from application_client.app_def import Errors


class CommandSender:
    """Base class to send APDU to the selected backend"""

    def __init__(self, backend: BackendInterface) -> None:
        """Class initializer"""

        self._backend = backend
        self._firmware = backend.firmware
        self._cmd_builder = CommandBuilder()


    def _exchange(self, payload: bytes) -> RAPDU:
        """Synchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Response APDU
        """

        return self._backend.exchange_raw(payload)


    @contextmanager
    def _exchange_async(self, payload: bytes) -> Generator[None, None, None]:
        """Asynchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Generator
        """

        with self._backend.exchange_async_raw(payload):
            yield


    def get_async_response(self) -> Optional[RAPDU]:
        """Asynchronous APDU response

        Returns:
            Response APDU
        """

        return self._backend.last_async_response


    def send_raw(self, cla: int, ins: int, p1: int, p2: int, payload: bytes) -> RAPDU:
        header = bytearray()
        header.append(cla)
        header.append(ins)
        header.append(p1)
        header.append(p2)
        header.append(len(payload))
        return self._exchange(header + payload)


    def get_version(self) -> bytes:
        """APDU Get Version

        Returns:
            Version data
        """

        rapdu = self._exchange(self._cmd_builder.get_version())
        assert rapdu.status == Errors.SW_SUCCESS
        return rapdu.data


    def get_serial(self) -> bytes:
        """APDU Get Serial

        Returns:
            Serial data
        """

        rapdu = self._exchange(self._cmd_builder.get_serial())
        assert rapdu.status == Errors.SW_SUCCESS
        return rapdu.data


    @contextmanager
    def derive_address_async(self, p1: P1Type, testCase: DeriveAddressTestCase) -> Generator[None, None, None]:
        """APDU Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            testCase (DeriveAddressTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.derive_address(p1, testCase)):
            yield


    def derive_address(self, p1: P1Type, testCase: DeriveAddressTestCase) -> RAPDU:
        """APDU Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            testCase (DeriveAddressTestCase): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.derive_address(p1, testCase))


    @contextmanager
    def get_pubkey_async(self, testCase: PubKeyTestCase) -> Generator[None, None, None]:
        """APDU Get Public Key

        Args:
            testCase (PubKeyTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.get_pubkey(testCase)):
            yield


    def get_pubkey(self, testCase: PubKeyTestCase) -> RAPDU:
        """APDU Get Public Key

        Args:
            testCase (PubKeyTestCase): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.get_pubkey(testCase))


    @contextmanager
    def sign_cip36_init(self, testCase: CVoteTestCase) -> Generator[None, None, None]:
        """APDU CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cip36_init(testCase)):
            yield


    def sign_cip36_chunk(self, testCase: CVoteTestCase) -> RAPDU:
        """APDU CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        chunks = self._cmd_builder.sign_cip36_chunk(testCase)
        for chunk in chunks[:-1]:
            resp = self._exchange(chunk)
            assert resp.status == Errors.SW_SUCCESS
        return self._exchange(chunks[-1])


    @contextmanager
    def sign_cip36_confirm(self) -> Generator[None, None, None]:
        """APDU CIP36 Vote - CONFIRM step

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cip36_confirm()):
            yield


    @contextmanager
    def sign_cip36_witness(self, testCase: CVoteTestCase) -> Generator[None, None, None]:
        """APDU CIP36 Vote - WITNESS step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cip36_witness(testCase)):
            yield


    @contextmanager
    def sign_opCert(self, testCase: OpCertTestCase) -> Generator[None, None, None]:
        """APDU Sign Operational Certificate

        Args:
            testCase (OpCertTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_opCert(testCase)):
            yield
