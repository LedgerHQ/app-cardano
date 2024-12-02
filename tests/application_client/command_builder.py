# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command building part.
"""

from enum import IntEnum
from typing import List, Optional

from ragger.bip import pack_derivation_path

from input_files.derive_address import DeriveAddressTestCase
from input_files.pubkey import PubKeyTestCase
from input_files.cvote import MAX_CIP36_PAYLOAD_SIZE, CVoteTestCase
from input_files.signOpCert import OpCertTestCase
from input_files.signMsg import SignMsgTestCase, MessageAddressFieldType
from input_files.signTx import SignTxTestCase, TxInput, TxOutput, Certificate, Withdrawal
from input_files.signTx import TxAuxiliaryData, TxAuxiliaryDataHash, DRepParams
from input_files.signTx import TxOutputDestinationType, TxOutputDestination
from input_files.signTx import TxOutputBabbage, ThirdPartyAddressParams
from input_files.signTx import CertificateType, CredentialParams, RequiredSigner
from input_files.signTx import VoterVotes, AnchorParams, TxAuxiliaryDataCIP36
from input_files.signTx import CIP36VoteDelegationType, AssetGroup, Token, Datum, DatumType
from input_files.signTx import MAX_SIGN_TX_CHUNK_SIZE

from application_client.app_def import InsType, AddressType, StakingDataSourceType


class P1Type(IntEnum):
    # Derive Address
    P1_RETURN = 0x01
    P1_DISPLAY = 0x02
    # Sign CIP36 Vote
    P1_INIT = 0x01
    P1_CHUNK = 0x02
    P1_CONFIRM = 0x03
    P1_WITNESS = 0x04
    # SignTx
    P1_INPUTS = 0x02
    P1_OUTPUTS = 0x03
    P1_FEE = 0x04
    P1_TTL = 0x05
    P1_CERTIFICATES = 0x06
    P1_WITHDRAWALS = 0x07
    P1_AUX_DATA = 0x08
    P1_VALIDITY_INTERVAL_START = 0x09
    P1_TX_CONFIRM = 0x0a
    P1_MINT = 0x0b
    P1_SCRIPT_DATA_HASH = 0x0c
    P1_COLLATERAL_INPUTS = 0x0d
    P1_REQUIRED_SIGNERS = 0x0e
    P1_TX_WITNESSES = 0x0f
    P1_TOTAL_COLLATERAL = 0x10
    P1_REFERENCE_INPUTS = 0x11
    P1_COLLATERAL_OUTPUT = 0x12
    P1_VOTING_PROCEDURES = 0x13
    P1_TREASURY = 0x15
    P1_DONATION = 0x16


class P2Type(IntEnum):
    # SignTx Outputs
    P2_BASIC_DATA = 0x30
    P2_DATUM = 0x34
    P2_DATUM_CHUNK = 0x35
    P2_SCRIPT = 0x36
    P2_SCRIPT_CHUNK = 0x37
    P2_CONFIRM = 0x33
    # SignTx Aux Data
    P2_INIT = 0x36
    P2_VOTE_KEY = 0x30
    P2_DELEGATION = 0x37
    P2_STAKING_KEY = 0x31
    P2_PAYMENT_ADDRESS = 0x32
    P2_NONCE = 0x33
    P2_VOTING_PURPOSE = 0x35
    P2_AUX_CONFIRM = 0x34
    # SignTx Asset Group
    ASSET_GROUP = 0x31
    TOKEN = 0x32


class CommandBuilder:
    _CLA: int = 0xd7

    def _serialize(self,
                   ins: InsType,
                   p1: int = 0x00,
                   p2: int = 0x00,
                   cdata: bytes = bytes()) -> bytes:

        header = bytearray()
        header.append(self._CLA)
        header.append(ins)
        header.append(p1)
        header.append(p2)
        header.append(len(cdata))
        return header + cdata


    def get_version(self) -> bytes:
        """APDU Builder for App version"""

        return self._serialize(InsType.GET_VERSION)


    def get_serial(self) -> bytes:
        """APDU Builder for App serial"""

        return self._serialize(InsType.GET_SERIAL)


    def derive_address(self, p1: P1Type, testCase: DeriveAddressTestCase) -> bytes:
        """APDU Builder for Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            testCase (DeriveAddressTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        data = self._serializeAddressParams(testCase)
        return self._serialize(InsType.DERIVE_PUBLIC_ADDR, p1, 0x00, data)


    def get_pubkey(self, testCase: PubKeyTestCase) -> bytes:
        """APDU Builder for Public Key

        Args:
            testCase (PubKeyTestCase): Test parameters

        Returns:
            Response APDU
        """

        data = bytes()
        data += pack_derivation_path(testCase.path)
        return self._serialize(InsType.GET_PUBLIC_ADDR, 0x00, 0x00, data)


    def sign_cip36_init(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Full length of voteCastDataHex (4B)
        #    voteCastDataHex (up to 240 B)
        data = bytes()
        # 2 hex chars per byte
        data_size = int(len(testCase.cVote.voteCastDataHex) / 2)
        chunk_size = min(MAX_CIP36_PAYLOAD_SIZE * 2, len(testCase.cVote.voteCastDataHex))
        data += data_size.to_bytes(4, "big")
        data += bytes.fromhex(testCase.cVote.voteCastDataHex[:chunk_size])
        # Remove the data sent in this step
        testCase.cVote.voteCastDataHex = testCase.cVote.voteCastDataHex[chunk_size:]
        return self._serialize(InsType.SIGN_CIP36_VOTE, P1Type.P1_INIT, 0x00, data)


    def sign_cip36_chunk(self, testCase: CVoteTestCase) -> List[bytes]:
        """APDU Builder for CIP36 Vote - CHUNK step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        # Serialization format:
        #    voteCastDataHex (following data, up to MAX_CIP36_PAYLOAD_SIZE B each)
        chunks = []
        payload = testCase.cVote.voteCastDataHex
        max_payload_size = MAX_CIP36_PAYLOAD_SIZE * 2 # 2 hex chars per byte
        while len(payload) > 0:
            chunks.append(self._serialize(InsType.SIGN_CIP36_VOTE,
                                          P1Type.P1_CHUNK,
                                          0x00,
                                          bytes.fromhex(payload[:max_payload_size])))
            payload = payload[max_payload_size:]

        return chunks


    def sign_cip36_confirm(self) -> bytes:
        """APDU Builder for CIP36 Vote - CONFIRM step

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_CIP36_VOTE, P1Type.P1_CONFIRM, 0x00)


    def sign_cip36_witness(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - WITNESS step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #     witness path (1B for length + [0-10] x 4B)
        return self._serialize(InsType.SIGN_CIP36_VOTE,
                               P1Type.P1_WITNESS,
                               0x00,
                               pack_derivation_path(testCase.cVote.witnessPath))


    def sign_opCert(self, testCase: OpCertTestCase) -> bytes:
        """APDU Builder for Sign Operational Certificate

        Args:
            testCase (OpCertTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        # kesPublicKeyHex hex string (32B)
        # kesPeriod (8B)
        # issueCounter (8B)
        # derivation path (1B for length + [0-10] x 4B)
        data = bytes()
        data += bytes.fromhex(testCase.opCert.kesPublicKeyHex)
        data += testCase.opCert.kesPeriod.to_bytes(8, "big")
        data += testCase.opCert.issueCounter.to_bytes(8, "big")
        data += pack_derivation_path(testCase.opCert.path)
        return self._serialize(InsType.SIGN_OP_CERT, 0x00, 0x00, data)


    def sign_msg_init(self, testCase: SignMsgTestCase) -> bytes:
        """APDU Builder for Sign Message - INIT step

        Args:
            testCase (SignMsgTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Full length of messageHex (4B)
        #    signingPath (1B for length + [0-10] x 4B)
        #    hashPayload (1B)
        #    isAscii display (1B)
        #    addressFieldType (1B)
        #    addressBuffer, if any
        data = bytes()
        # 2 hex chars per byte
        data_size = int(len(testCase.msgData.messageHex) / 2)
        data += data_size.to_bytes(4, "big")
        data += pack_derivation_path(testCase.msgData.signingPath)

        data += testCase.msgData.hashPayload.to_bytes(1, "big")
        data += testCase.msgData.isAscii.to_bytes(1, "big")
        data += testCase.msgData.addressFieldType.to_bytes(1, "big")
        if testCase.msgData.addressFieldType == MessageAddressFieldType.ADDRESS:
            assert testCase.msgData.addressDesc is not None
            data += self._serializeAddressParams(testCase.msgData.addressDesc)
        return self._serialize(InsType.SIGN_MSG, P1Type.P1_INIT, 0x00, data)


    def sign_msg_chunk(self, testCase: SignMsgTestCase) -> List[bytes]:
        """APDU Builder for Sign Message - CHUNK step

        Args:
            testCase (SignMsgTestCase): Test parameters

        Returns:
            Response APDU
        """

        MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE = 198 * 2
        MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE = 99 * 2
        MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE = 250 * 2
        # Serialization format:
        #    messageHex (up to MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE B each, started by the length)
        chunks = []
        if testCase.msgData.isAscii:
            firstChunkSize = MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE
        else:
            firstChunkSize = MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE
        chunk_size = min(firstChunkSize, len(testCase.msgData.messageHex))
        payload = testCase.msgData.messageHex
        while True:
            data = bytes()
            data += int(chunk_size / 2).to_bytes(4, "big")
            data += bytes.fromhex(payload[:chunk_size])
            chunks.append(self._serialize(InsType.SIGN_MSG, P1Type.P1_CHUNK, 0x00, data))
            payload = payload[chunk_size:]
            chunk_size = min(MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE, len(payload))
            if len(payload) == 0:
                break

        return chunks


    def sign_msg_confirm(self) -> bytes:
        """APDU Builder for Sign Message - CONFIRM step

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_MSG, P1Type.P1_CONFIRM, 0x00)


    def sign_tx_init(self, testCase: SignTxTestCase, nbWitnessPaths: int) -> bytes:
        """APDU Builder for Sign TX - INIT step

        Args:
            testCase (SignTxTestCase): Test parameters
            nbWitnessPaths (int): The number of unique witness paths

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Options (8B)
        #    NetworkId (1B)
        #    ProtocolMagic (4B)
        #    TTL option flag (1B)
        #    auxiliary Data option flag (1B)
        #    validityIntervalStart option flag (1B)
        #    mint
        #    scriptDataHash
        #    includeNetworkId
        #    collateralOutput
        #    totalCollateral
        #    treasury
        #    donation
        #    signingMode
        #    TX inputs length (4B)
        #    TX outputs length (4B)
        #    TX certificates length (4B)
        #    TX withdrawals length (4B)
        #    witnessLegacy
        #    collateralInputs
        #    requiredSigners
        #    referenceInputs
        #    votingProcedures
        #    witnessBabbage
        data = bytes()
        data += testCase.options.to_bytes(8, "big")
        data += testCase.tx.network.networkId.to_bytes(1, "big")
        data += testCase.tx.network.protocol.to_bytes(4, "big")
        data += self._serializeOptionFlags(testCase.tx.ttl is not None)
        data += self._serializeOptionFlags(testCase.tx.auxiliaryData is not None)
        data += self._serializeOptionFlags(testCase.tx.validityIntervalStart is not None)
        data += self._serializeOptionFlags(len(testCase.tx.mint) > 0)
        data += self._serializeOptionFlags(testCase.tx.scriptDataHash is not None)
        data += self._serializeOptionFlags(testCase.tx.includeNetworkId is not None)
        data += self._serializeOptionFlags(testCase.tx.collateralOutput is not None)
        data += self._serializeOptionFlags(testCase.tx.totalCollateral is not None)
        data += self._serializeOptionFlags(testCase.tx.treasury is not None)
        data += self._serializeOptionFlags(testCase.tx.donation is not None)
        data += testCase.signingMode.to_bytes(1, "big")
        data += len(testCase.tx.inputs).to_bytes(4, "big")
        data += len(testCase.tx.outputs).to_bytes(4, "big")
        data += len(testCase.tx.certificates).to_bytes(4, "big")
        data += len(testCase.tx.withdrawals).to_bytes(4, "big")
        data += len(testCase.tx.collateralInputs).to_bytes(4, "big")
        data += len(testCase.tx.requiredSigners).to_bytes(4, "big")
        data += len(testCase.tx.referenceInputs).to_bytes(4, "big")
        data += len(testCase.tx.votingProcedures).to_bytes(4, "big")
        data += nbWitnessPaths.to_bytes(4, "big")
        return self._serialize(InsType.SIGN_TX, P1Type.P1_INIT, 0x00, data)


    def sign_tx_aux_data_hash(self, auxData: TxAuxiliaryData) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - ARBITRARY_HASH mode

        Args:
            auxData (TxAuxiliaryData): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Type (1B)
        #    HashHex bytes
        data = bytes()
        data += auxData.type.to_bytes(1, "big")
        if isinstance(auxData.params, TxAuxiliaryDataHash):
            data += bytes.fromhex(auxData.params.hashHex)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, 0x00, data)


    def sign_tx_aux_data_init(self, auxData: TxAuxiliaryDataCIP36) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - INIT mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Type (1B)
        #    Nb of delegations (4B)
        data = bytes()
        data += auxData.format.to_bytes(1, "big")
        numDelegation = len(auxData.delegations)
        data += numDelegation.to_bytes(4, "big")
        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, P2Type.P2_INIT, data)


    def sign_tx_aux_data_vote_key(self, auxData: TxAuxiliaryDataCIP36) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - VOTE KEY mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Type (1B)
        #    Vote Key Hex
        data = bytes()
        if auxData.voteKeyHex is not None:
            data += CIP36VoteDelegationType.KEY.to_bytes(1, "big")
            assert auxData.voteKeyHex is not None
            data += bytes.fromhex(auxData.voteKeyHex)
        else:
            data += CIP36VoteDelegationType.PATH.to_bytes(1, "big")
            assert auxData.voteKeyPath is not None
            data += bytes.fromhex(auxData.voteKeyPath)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, P2Type.P2_VOTE_KEY, data)


    def sign_tx_aux_data_staking(self, auxData: TxAuxiliaryDataCIP36) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - STAKING mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Staking Path or Hash
        data = bytes()
        if auxData.stakingPath.startswith("m/"):
            data += pack_derivation_path(auxData.stakingPath)
        else:
            data = bytes.fromhex(auxData.stakingPath)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, P2Type.P2_STAKING_KEY, data)


    def sign_tx_aux_data_payment(self, auxData: TxAuxiliaryDataCIP36) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - PAYMENT mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Payment destination
        data = self._serializeTxOutputDestination(auxData.paymentDestination)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, P2Type.P2_PAYMENT_ADDRESS, data)


    def sign_tx_aux_data_nonce(self, auxData: TxAuxiliaryDataCIP36) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - NONCE mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Nonce (8B)
        data = auxData.nonce.to_bytes(8, "big")
        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, P2Type.P2_NONCE, data)


    def sign_tx_aux_data_voting_purpose(self, auxData: TxAuxiliaryDataCIP36) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - VOTING PURPOSE mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Voting Purpose option flag (1B)
        #    Voting Purpose
        data = bytes()
        data += self._serializeOptionFlags(auxData.votingPurpose is not None)
        if auxData.votingPurpose is not None:
            data += auxData.votingPurpose.to_bytes(8, "big")
        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, P2Type.P2_VOTING_PURPOSE, data)


    def sign_tx_aux_data_confirm(self) -> bytes:
        """APDU Builder for Sign TX - AUX DATA step - CONFIRM mode

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_TX, P1Type.P1_AUX_DATA, P2Type.P2_AUX_CONFIRM)


    def sign_tx_inputs(self, txInput: TxInput) -> bytes:
        """APDU Builder for Sign TX - INPUTS step

        Args:
            txInput (TxInput): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Tx Hash Hex
        #    Tx Output Index (4B)
        data = bytes()
        data += bytes.fromhex(txInput.txHashHex)
        data += txInput.outputIndex.to_bytes(4, "big")
        return self._serialize(InsType.SIGN_TX, P1Type.P1_INPUTS, 0x00, data)


    def sign_tx_outputs_basic(self, txOutput: TxOutput) -> bytes:
        """APDU Builder for Sign TX - OUTPUTS step - BASIC DATA level

        Args:
            txOutput (TxOutput): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Format (1B)
        #    Tx Output destination
        #    Coin (8B)
        #    TokenBundle Length (4B)
        #    datum option flag (1B)
        #    referenceScriptHex option flag (1B)
        data = bytes()
        data += txOutput.format.to_bytes(1, "big")
        data += self._serializeTxOutputDestination(txOutput.destination)
        data += self._serializeCoin(txOutput.amount)
        data += len(txOutput.tokenBundle).to_bytes(4, "big")
        data += self._serializeOptionFlags(txOutput.datum is not None)
        if isinstance(txOutput, TxOutputBabbage):
            data += self._serializeOptionFlags(txOutput.referenceScriptHex is not None)
        else:
            data += self._serializeOptionFlags(False)

        return self._serialize(InsType.SIGN_TX, P1Type.P1_OUTPUTS, P2Type.P2_BASIC_DATA, data)


    def sign_tx_outputs_datum(self, datum: Datum) -> bytes:
        """APDU Builder for Sign TX - OUTPUTS step - DATUM level

        Args:
            txInput (TxInput): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Type (1B)
        #    Datum 1st Chunk
        data = bytes()
        data += datum.type.to_bytes(1, "big")
        if datum.type == DatumType.INLINE:
            data += self._serializeTxChunk(datum.datumHex)
        else:
            data += bytes.fromhex(datum.datumHex)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_OUTPUTS, P2Type.P2_DATUM, data)


    def sign_tx_outputs_ref_script(self, referenceScriptHex: str) -> bytes:
        """APDU Sign TX - OUTPUTS step - REFERENCE SCRIPT level

        Args:
            referenceScriptHex (str): Test parameters

        Returns:
            Response APDU
        """

        #    Reference Script Chunk
        data = self._serializeTxChunk(referenceScriptHex)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_OUTPUTS, P2Type.P2_SCRIPT, data)


    def sign_tx_outputs_chunk(self, p2: P2Type, chunkHex: str) -> bytes:
        """APDU Sign TX - OUTPUTS step - xxx CHUNKS level

        Args:
            p2 (P2Type): APDU Parameter 2
            chunkHex (str): Test parameters

        Returns:
            Response APDU
        """

        #    Script Chunk
        length = len(chunkHex) // 2
        data = bytes()
        data += length.to_bytes(4, "big")
        data += bytes.fromhex(chunkHex)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_OUTPUTS, p2, data)


    def sign_tx_outputs_confirm(self) -> bytes:
        """APDU Builder for Sign TX - OUTPUTS step - CONFIRM level

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_TX, P1Type.P1_OUTPUTS, P2Type.P2_CONFIRM)


    def sign_tx_fee(self, testCase: SignTxTestCase) -> bytes:
        """APDU Builder for Sign TX - FEE step

        Args:
            testCase (SignTxTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Fee (8B)
        data = self._serializeCoin(testCase.tx.fee)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_FEE, 0x00, data)


    def sign_tx_ttl(self, testCase: SignTxTestCase) -> bytes:
        """APDU Builder for Sign TX - TTL step

        Args:
            testCase (SignTxTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    TTL (8B)
        assert testCase.tx.ttl is not None
        data = self._serializeCoin(testCase.tx.ttl)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_TTL, 0x00, data)


    def sign_tx_withdrawal(self, withdrawal: Withdrawal) -> bytes:
        """APDU Builder for Sign TX - WITHDRAWAL step

        Args:
            withdrawal (Withdrawal): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Amount (8B)
        #    Staking cresentials
        data = bytes()
        data += self._serializeCoin(withdrawal.amount)
        data += self._serializeCredential(withdrawal.stakeCredential)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_WITHDRAWALS, 0x00, data)


    def sign_tx_validity(self, validity: int) -> bytes:
        """APDU Builder for Sign TX - VALIDITY START step

        Args:
            validity (int): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Validity Start (8B)
        data = validity.to_bytes(8, "big")
        return self._serialize(InsType.SIGN_TX, P1Type.P1_VALIDITY_INTERVAL_START, 0x00, data)


    def sign_tx_mint_init(self, nbMints: int) -> bytes:
        """APDU Builder for Sign TX - MINT step - INIT mode

        Args:
            nbMints (int): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Nb of mint elements (4B)
        data = nbMints.to_bytes(4, "big")
        return self._serialize(InsType.SIGN_TX, P1Type.P1_MINT, P2Type.P2_BASIC_DATA, data)


    def sign_tx_mint_confirm(self) -> bytes:
        """APDU Builder for Sign TX - MINT step - CONFIRM mode

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_TX, P1Type.P1_MINT, P2Type.P2_CONFIRM)


    def sign_tx_asset_group(self, p1: P1Type, asset: AssetGroup) -> bytes:
        """APDU Builder for Sign TX - TOKEN BUNDLE step - ASSET mode

        Args:
            p1 (P1Type): APDU Parameter 1
            asset (AssetGroup): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Asset Group
        data = self._serializeAssetGroup(asset)
        return self._serialize(InsType.SIGN_TX, p1, P2Type.ASSET_GROUP, data)


    def sign_tx_token(self, p1: P1Type, token: Token) -> bytes:
        """APDU Builder for Sign TX - TOKEN BUNDLE step - TOKEN mode

        Args:
            p1 (P1Type): APDU Parameter 1
            asset (AssetGroup): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Asset Token
        data = self._serializeToken(token)
        return self._serialize(InsType.SIGN_TX, p1, P2Type.TOKEN, data)


    def sign_tx_script_data_hash(self, script: str) -> bytes:
        """APDU Builder for Sign TX - SCRIPT DATA HASH step

        Args:
            script (str): Input Test script data hash

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Script Data Hash
        data = bytes.fromhex(script)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_SCRIPT_DATA_HASH, 0x00, data)


    def sign_tx_collateral_inputs(self, txInput: TxInput) -> bytes:
        """APDU Builder for Sign TX - COLLATERAL INPUTS step

        Args:
            txInput (TxInput): Input Test data

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Collateral Input
        data = self._serializeTxInput(txInput)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_COLLATERAL_INPUTS, 0x00, data)


    def sign_tx_total_collateral(self, total: int) -> bytes:
        """APDU Builder for Sign TX - TOTAL COLLATERAL step

        Args:
            total (int): Input Test data

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Nb of collateral elements (8B)
        data = self._serializeCoin(total)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_TOTAL_COLLATERAL, 0x00, data)


    def sign_tx_reference_inputs(self, txInput: TxInput) -> bytes:
        """APDU Builder for Sign TX - REFERENCE INPUTS step

        Args:
            txInput (TxInput): Input Test data

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Reference Input
        data = self._serializeTxInput(txInput)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_REFERENCE_INPUTS, 0x00, data)


    def sign_tx_collateral_output_basic(self, txOutput: TxOutput) -> bytes:
        """APDU Builder for Sign TX - COLLATERAL OUTPUTS step - BASIC DATA level

        Args:
            txOutput (TxOutput): Input Test data

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Format (1B)
        #    Tx Output destination
        #    Coin (8B)
        #    TokenBundle Length (4B)
        #    datum option flag (1B)
        #    referenceScriptHex option flag (1B)
        data = bytes()
        data += txOutput.format.to_bytes(1, "big")
        data += self._serializeTxOutputDestination(txOutput.destination)
        data += self._serializeCoin(txOutput.amount)
        data += len(txOutput.tokenBundle).to_bytes(4, "big")
        data += self._serializeOptionFlags(txOutput.datum is not None)
        if isinstance(txOutput, TxOutputBabbage):
            data += self._serializeOptionFlags(txOutput.referenceScriptHex is not None)
        else:
            data += self._serializeOptionFlags(False)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_COLLATERAL_OUTPUT, P2Type.P2_BASIC_DATA, data)


    def sign_tx_collateral_output_confirm(self) -> bytes:
        """APDU Builder for Sign TX - COLLATERAL OUTPUTS step - CONFIRM level

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_TX, P1Type.P1_COLLATERAL_OUTPUT, P2Type.P2_CONFIRM)


    def sign_tx_required_signers(self, signer: RequiredSigner) -> bytes:
        """APDU Builder for Sign TX - REQUIRED SIGNERS step

        Args:
            signer (RequiredSigner): Input Test data

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Type (1B)
        #    Address
        data = signer.type.to_bytes(1, "big")
        if signer.addressHex.startswith("m/"):
            data += pack_derivation_path(signer.addressHex)
        else:
            data += bytes.fromhex(signer.addressHex)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_REQUIRED_SIGNERS, 0x00, data)


    def sign_tx_treasury(self, treasury: int) -> bytes:
        """APDU Builder for Sign TX - TREASURY step

        Args:
            treasury (int): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Coin (8B)
        data = self._serializeCoin(treasury)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_TREASURY, 0x00, data)


    def sign_tx_donation(self, donation: int) -> bytes:
        """APDU Builder for Sign TX - DONATION step

        Args:
            donation (int): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Coin (8B)
        data = self._serializeCoin(donation)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_DONATION, 0x00, data)


    def sign_tx_voting_procedure(self, votingProcedure: VoterVotes) -> bytes:
        """APDU Builder for Sign TX - VOTING PROCEDURES step

        Args:
            votingProcedure (VoterVotes): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Voter Type (1B)
        #    Voter Key
        #    Gov Action Tx Hash
        #    Gov Action Index (4B)
        #    Vote (1B)
        #    Anchor
        assert len(votingProcedure.votes) == 1
        data = bytes()
        data += votingProcedure.voter.type.to_bytes(1, "big")
        if votingProcedure.voter.keyValue.startswith("m/"):
            data += pack_derivation_path(votingProcedure.voter.keyValue)
        else:
            data += bytes.fromhex(votingProcedure.voter.keyValue)
        data += bytes.fromhex(votingProcedure.votes[0].govActionId.txHashHex)
        data += votingProcedure.votes[0].govActionId.govActionIndex.to_bytes(4, "big")
        data += votingProcedure.votes[0].votingProcedure.vote.to_bytes(1, "big")
        data += self._serializeAnchor(votingProcedure.votes[0].votingProcedure.anchor)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_VOTING_PROCEDURES, 0x00, data)


    def sign_tx_certificate(self, certificate: Certificate) -> bytes:
        """APDU Builder for Sign TX - WITHDRAWAL step

        Args:
            certificate (Certificate): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #   Certificate Type (1B)
        #   Certificate Data
        data = bytes()
        if certificate.type in (CertificateType.STAKE_REGISTRATION, CertificateType.STAKE_DEREGISTRATION):
            data += certificate.type.to_bytes(1, "big")
            assert certificate.stakeCredential is not None
            data += self._serializeCredential(certificate.stakeCredential)
        elif certificate.type in (CertificateType.STAKE_REGISTRATION_CONWAY, CertificateType.STAKE_DEREGISTRATION_CONWAY):
            data += certificate.type.to_bytes(1, "big")
            assert certificate.stakeCredential is not None
            data += self._serializeCredential(certificate.stakeCredential)
            assert certificate.deposit is not None
            data += self._serializeCoin(certificate.deposit)
        elif certificate.type == CertificateType.STAKE_DELEGATION:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.stakeCredential is not None
            data += self._serializeCredential(certificate.stakeCredential)
            assert certificate.poolKey is not None
            data += bytes.fromhex(certificate.poolKey)
        elif certificate.type == CertificateType.VOTE_DELEGATION:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.stakeCredential is not None
            data += self._serializeCredential(certificate.stakeCredential)
            assert certificate.dRep is not None
            data += self._serializeDRep(certificate.dRep)
        elif certificate.type == CertificateType.AUTHORIZE_COMMITTEE_HOT:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.coldCredential is not None
            data += self._serializeCredential(certificate.coldCredential)
            assert certificate.hotCredential is not None
            data += self._serializeCredential(certificate.hotCredential)
        elif certificate.type == CertificateType.RESIGN_COMMITTEE_COLD:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.coldCredential is not None
            data += self._serializeCredential(certificate.coldCredential)
            data += self._serializeAnchor(certificate.anchor)
        elif certificate.type == CertificateType.DREP_REGISTRATION:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.dRepCredential is not None
            data += self._serializeCredential(certificate.dRepCredential)
            assert certificate.deposit is not None
            data += self._serializeCoin(certificate.deposit)
            data += self._serializeAnchor(certificate.anchor)
        elif certificate.type == CertificateType.DREP_DEREGISTRATION:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.dRepCredential is not None
            data += self._serializeCredential(certificate.dRepCredential)
            assert certificate.deposit is not None
            data += self._serializeCoin(certificate.deposit)
        elif certificate.type == CertificateType.DREP_UPDATE:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.dRepCredential is not None
            data += self._serializeCredential(certificate.dRepCredential)
            data += self._serializeAnchor(certificate.anchor)
        elif certificate.type == CertificateType.STAKE_POOL_REGISTRATION:
            data += certificate.type.to_bytes(1, "big")
        elif certificate.type == CertificateType.STAKE_POOL_RETIREMENT:
            data += certificate.type.to_bytes(1, "big")
            assert certificate.poolKey is not None
            if certificate.poolKey.startswith("m/"):
                data += pack_derivation_path(certificate.poolKey)
            else:
                data += bytes.fromhex(certificate.poolKey)
            assert certificate.retirementEpoch is not None
            data += certificate.retirementEpoch.to_bytes(8, "big")
        elif certificate.type == CertificateType.VOTE_DELEGATION:
            data += certificate.type.to_bytes(1, "big")
            data += self._serializeCredential(certificate.stakeCredential)
            assert certificate.dRep is not None
            data += self._serializeDRep(certificate.dRep)
        else:
            raise NotImplementedError("Not implemented yet")

        return self._serialize(InsType.SIGN_TX, P1Type.P1_CERTIFICATES, 0x00, data)


    def sign_tx_confirm(self) -> bytes:
        """APDU Builder for Sign TX - CONFIRM step

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_TX, P1Type.P1_TX_CONFIRM)


    def sign_tx_witness(self, path: str) -> bytes:
        """APDU Builder for Sign TX - WITNESS step

        Args:
            path (str): Input Test path

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Witness Path
        data = pack_derivation_path(path)
        return self._serialize(InsType.SIGN_TX, P1Type.P1_TX_WITNESSES, 0x00, data)


    def _serializeTxChunk(self, referenceHex: str) -> bytes:
        """Serialize TX Chunk"""

        # Serialization format:
        #    Full data length (4B)
        #    Chunk size (4B)
        #    Chunk data
        data = bytes()
        totalSize = len(referenceHex) // 2
        data += totalSize.to_bytes(4, "big")
        if totalSize > MAX_SIGN_TX_CHUNK_SIZE:
            chunkHex = referenceHex[:MAX_SIGN_TX_CHUNK_SIZE * 2]
        else:
            chunkHex = referenceHex
        chunkSize = len(chunkHex) // 2
        data += chunkSize.to_bytes(4, "big")
        data += bytes.fromhex(chunkHex)
        return data


    def _serializeTxInput(self, txInput: TxInput) -> bytes:
        """Serialize TX Input"""

        # Serialization format:
        #    Input Hash
        #    Output Index (4B)
        data = bytes()
        data += bytes.fromhex(txInput.txHashHex)
        data += txInput.outputIndex.to_bytes(4, "big")
        return data


    def _serializeAnchor(self, anchor: Optional[AnchorParams] = None) -> bytes:
        """Serialize Anchor"""

        # Serialization format:
        #    Anchor option flag (1B)
        #    Anchor hash
        #    Anchor URL
        data = bytes()
        data += self._serializeOptionFlags(anchor is not None)
        if anchor is not None:
            data += bytes.fromhex(anchor.hashHex)
            data += anchor.url.encode("ascii")
        return data


    def _serializeOptionFlags(self, included: bool) -> bytes:
        """Serialize Flag option value"""

        # Serialization format:
        #    Flag value (1B): 02 if included, 01 otherwise
        value = 0x02 if included else 0x01
        return value.to_bytes(1, "big")


    def _serializeCoin(self, coin: int) -> bytes:
        """Serialize Coin value"""

        return coin.to_bytes(8, "big")


    def _serializeCredential(self, credential: CredentialParams) -> bytes:
        """Serialize Credential"""

        # Serialization format:
        #    Type (1B)
        #    Credential data
        data = bytes()
        data += credential.type.to_bytes(1, "big")
        assert credential.keyValue is not None
        if credential.keyValue.startswith("m/"):
            data += pack_derivation_path(credential.keyValue)
        else:
            data += bytes.fromhex(credential.keyValue)
        return data


    def _serializeDRep(self, dRep: DRepParams) -> bytes:
        """Serialize DRep"""

        # Serialization format:
        #    Type (1B)
        #    DRep data
        data = bytes()
        data += dRep.type.to_bytes(1, "big")
        if dRep.keyValue is not None:
            if dRep.keyValue.startswith("m/"):
                data += pack_derivation_path(dRep.keyValue)
            else:
                data += bytes.fromhex(dRep.keyValue)
        return data


    def _serializeTxOutputDestination(self, outDest: TxOutputDestination) -> bytes:
        """Serialize TX Output Destination"""

        # Serialization format:
        #    Type (1B)
        #    Destination data
        data = bytes()
        data += outDest.type.to_bytes(1, "big")
        if outDest.type == TxOutputDestinationType.THIRD_PARTY:
            assert isinstance(outDest.params, ThirdPartyAddressParams)
            data += int(len(outDest.params.addressHex) / 2).to_bytes(4, "big")
            data += bytes.fromhex(outDest.params.addressHex)
        else:
            assert isinstance(outDest.params, DeriveAddressTestCase)
            data += self._serializeAddressParams(outDest.params)
        return data


    def _serializeAddressParams(self, testCase: DeriveAddressTestCase) -> bytes:
        """Serialize address parameters"""

        # Serialization format (from the documentation):
        # address type 1B
        # if address type == BYRON
        #     protocol magic 4B
        # else
        #     network id 1B
        # payment public key derivation path (1B for length + [0-10] x 4B) or script hash 28B
        # staking choice 1B
        #     if NO_STAKING:
        #         nothing more
        #     if STAKING_KEY_PATH:
        #         staking public key derivation path (1B for length + [0-10] x 4B)
        #     if STAKING_KEY_HASH:
        #         stake key hash 28B
        #     if BLOCKCHAIN_POINTER:
        #         certificate blockchain pointer 3 x 4B
        data = bytes()
        data += testCase.addrType.to_bytes(1, "big")
        if testCase.addrType == AddressType.BYRON:
            data += testCase.netDesc.protocol.to_bytes(4, "big")
        else:
            data += testCase.netDesc.networkId.to_bytes(1, "big")

        if not testCase.spendingValue.startswith("m/"):
            data += bytes.fromhex(testCase.spendingValue)
        elif testCase.spendingValue:
            data += pack_derivation_path(testCase.spendingValue)

        if testCase.addrType in (AddressType.BYRON, AddressType.ENTERPRISE_KEY,
                        AddressType.ENTERPRISE_SCRIPT):
            staking = StakingDataSourceType.NONE
        elif testCase.addrType in (AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
                          AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
                          AddressType.REWARD_SCRIPT):
            staking = StakingDataSourceType.SCRIPT_HASH
        elif testCase.addrType in (AddressType.POINTER_KEY, AddressType.POINTER_SCRIPT):
            staking = StakingDataSourceType.BLOCKCHAIN_POINTER
        elif not testCase.stakingValue.startswith("m/"):
            staking = StakingDataSourceType.KEY_HASH
        else:
            staking = StakingDataSourceType.KEY_PATH
        data += staking.to_bytes(1, "big")

        if staking == StakingDataSourceType.KEY_PATH:
            data += pack_derivation_path(testCase.stakingValue)
        elif staking in (StakingDataSourceType.KEY_HASH,
                         StakingDataSourceType.SCRIPT_HASH,
                         StakingDataSourceType.BLOCKCHAIN_POINTER):
            data += bytes.fromhex(testCase.stakingValue)
        elif staking != StakingDataSourceType.NONE:
            raise NotImplementedError("Not implemented yet")

        return data


    def _serializeAssetGroup(self, asset: AssetGroup) -> bytes:
        """Serialize Asset Group"""

        # Serialization format:
        #    Policy ID
        #    Nb of tokens (4B)
        data = bytes()
        data += bytes.fromhex(asset.policyIdHex)
        data += len(asset.tokens).to_bytes(4, "big")
        return data


    def _serializeToken(self, token: Token) -> bytes:
        """Serialize Token"""

        # Serialization format:
        #    Asset Name Length (4B)
        #    Asset Name
        #    Amount (8B)
        data = bytes()
        data += int(len(token.assetNameHex) / 2).to_bytes(4, "big")
        data += bytes.fromhex(token.assetNameHex)
        data += token.amount.to_bytes(8, "big", signed=True)
        return data
