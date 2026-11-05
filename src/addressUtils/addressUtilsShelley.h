/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "cardano_constants.h"
#include "bip44.h"
#include "tx_credential_types.h"
#include "tx_address_types.h"
#include "utils.h"

typedef enum {
    // base address contains explicit payment info (key hash / script hash)
    // and explicit staking info
    BASE_PAYMENT_KEY_STAKE_KEY = 0x0,        // 0b0000
    BASE_PAYMENT_SCRIPT_STAKE_KEY = 0x1,     // 0b0001
    BASE_PAYMENT_KEY_STAKE_SCRIPT = 0x2,     // 0b0010
    BASE_PAYMENT_SCRIPT_STAKE_SCRIPT = 0x3,  // 0b0011

    // pointer address contains explicit payment info and a pointer to blockchain for staking info
    POINTER_KEY = 0x4,     // 0b0100
    POINTER_SCRIPT = 0x5,  // 0b0101

    // enterprise address contains explicit payment info and no staking info
    ENTERPRISE_KEY = 0x6,     // 0b0110
    ENTERPRISE_SCRIPT = 0x7,  // 0b0111

    // legacy addresses, aka bootstrap addresses
    BYRON = 0x8,  // 0b1000

    // reward address (aka reward account) contains only staking info
    REWARD_KEY = 0xE,     // 0b1110
    REWARD_SCRIPT = 0xF,  // 0b1111
} address_type_t;

// For Shelley, address is at most 1 + 28 + 28 = 57 bytes,
// encoded in bech32 as 10 (prefix) + 8/5 * 57 + 6 (checksum) = 108 chars.
// Reward accounts are just 1 + 28 = 29 bytes and therefore fit into
// MAX_HUMAN_ADDRESS_LENGTH as well.
// For Byron, the address can contain 64B of data (according to Duncan),
// plus 46B with empty data; 100B in base58 has length at most 139.
// (Previously, we used 128 bytes.)
// https://stackoverflow.com/questions/48333136/size-of-buffer-to-hold-base58-encoded-data
#define MAX_ADDRESS_LENGTH       128
#define MAX_HUMAN_ADDRESS_LENGTH 150

uint8_t getAddressHeader(const uint8_t *addressBuffer, size_t addressSize);

address_type_t getAddressType(uint8_t addressHeader);
bool isSupportedAddressType(uint8_t addressHeader);
bool isShelleyAddressType(uint8_t addressType);
bool isValidShelleyAddressLength(address_type_t addressType, size_t addressSize);
uint8_t constructShelleyAddressHeader(address_type_t type, uint8_t networkId);

uint8_t getNetworkId(uint8_t addressHeader);
bool isValidNetworkId(uint8_t networkId);

// Internal encoding of staking part representation inside address_params_t.
// Keep this typed for safety, but callers outside address utils should avoid
// branching on these values directly and instead use validation/helpers.
typedef enum {
    STAKING_PART_NONE = 0x11,
    STAKING_PART_KEY_PATH = 0x22,
    STAKING_PART_KEY_HASH = 0x33,
    STAKING_PART_BLOCKCHAIN_POINTER = 0x44,
    STAKING_PART_SCRIPT_HASH = 0x55,
} staking_part_type_t;

typedef enum {
    PAYMENT_PATH,
    PAYMENT_SCRIPT_HASH,
    PAYMENT_NONE,
} payment_choice_t;

// Internal encoding of payment part representation inside address_params_t.
// Keep this typed for safety, but callers outside address utils should avoid
// branching on these values directly and instead use validation/helpers.
typedef enum {
    PAYMENT_PART_KEY_PATH = 0x66,
    // Reserved for future use; currently not accepted by isValidAddressParams().
    PAYMENT_PART_KEY_HASH = 0x77,
    PAYMENT_PART_SCRIPT_HASH = 0x88,
    PAYMENT_PART_NONE = 0x99,
} payment_part_type_t;

typedef uint32_t blockchainIndex_t;  // must be unsigned

typedef struct {
    blockchainIndex_t blockIndex;
    blockchainIndex_t txIndex;
    blockchainIndex_t certificateIndex;
} blockchainPointer_t;

// Pointer-based address parameters.
// Hash pointers reference external buffers (raw_tx / raw_cvote_init_data / APDU),
// while key paths are stored by value.
typedef struct {
    address_type_t type;
    union {
        uint32_t protocolMagic;  // if type == BYRON
        uint8_t networkId;       // all the other types (i.e. Shelley)
    };

    // Internal representation detail; prefer address utils helpers for branching.
    payment_part_type_t paymentPartType;
    bip44_path_t paymentKeyPath;
    const uint8_t *paymentScriptHash;

    // Internal representation detail; prefer address utils helpers for branching.
    staking_part_type_t stakingPartType;

    bip44_path_t stakingKeyPath;
    const uint8_t *stakingKeyHash;
    blockchainPointer_t stakingKeyBlockchainPointer;
    const uint8_t *stakingScriptHash;
} address_params_t;

typedef struct {
    uint8_t paymentHash[SCRIPT_HASH_LENGTH];
    uint8_t stakingHash[ADDRESS_KEY_HASH_LENGTH];
} address_params_hashes_storage_t;

__noinline_due_to_stack__ size_t deriveAddress(const address_params_t *address_params,
                                               uint8_t *outBuffer,
                                               size_t outSize);

__noinline_due_to_stack__ size_t constructRewardAddressFromKeyPath(const bip44_path_t *path,
                                                                   uint8_t networkId,
                                                                   uint8_t *outBuffer,
                                                                   size_t outSize);

typedef enum {
    REWARD_HASH_SOURCE_KEY,
    REWARD_HASH_SOURCE_SCRIPT,
} reward_address_hash_source_t;

__noinline_due_to_stack__ size_t constructRewardAddressFromHash(uint8_t networkId,
                                                                reward_address_hash_source_t source,
                                                                const uint8_t *hashBuffer,
                                                                size_t hashSize,
                                                                uint8_t *outBuffer,
                                                                size_t outSize);

bool format_blockchain_pointer(blockchainPointer_t blockchainPointer, char *out, size_t outSize);

bool format_address_human_readable(const uint8_t *address,
                                   size_t addressSize,
                                   char *out,
                                   size_t outSize);
__noinline_due_to_stack__ bool format_reward_account_from_credential(
    uint8_t networkId,
    const ext_credential_t *credential,
    char *out,
    size_t outSize);

__noinline_due_to_stack__ bool format_pool_reward_account(
    uint8_t networkId,
    const pool_reward_account_t *rewardAccount,
    char *out,
    size_t outSize);

bool buffer_read_address_params(buffer_t *buffer, address_params_t *params);

/**
 * Copy any hash pointers inside address_params into storage and update pointers
 * to reference the storage buffers. Use this when the original buffer (e.g. APDU)
 * will be overwritten before params are consumed.
 */
void address_params_copyHashesToStorage(address_params_t *params,
                                        address_params_hashes_storage_t *storage);

bool isValidAddressParams(const address_params_t *address_params);
payment_choice_t determinePaymentChoice(address_type_t addressType);
payment_part_type_t addressParams_getPaymentPartType(const address_params_t *address_params);
staking_part_type_t addressParams_getStakingPartType(const address_params_t *address_params);

/**
 * Convert a reward account to its binary representation.
 * Handles both key path (device-owned) and key hash (third-party) references.
 *
 * @param rewardAccount The reward account structure containing either a key path or hash
 * @param networkId The network ID to use for the reward account
 * @param rewardAccountBuffer Output buffer to store the serialized reward account
 * (REWARD_ACCOUNT_LENGTH bytes)
 */
void poolRewardAccountToBuffer(const pool_reward_account_t *rewardAccount,
                               uint8_t networkId,
                               uint8_t *rewardAccountBuffer);
