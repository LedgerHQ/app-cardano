#pragma once
// General libraries
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef FUZZING
#define explicit_bzero(addr, size) memset((addr), 0, (size))
#endif

// ours
#include "assert.h"
#include "utils.h"

enum { P1_UNUSED = 0, P2_UNUSED = 0 };

enum { ITEM_INCLUDED_NO = 1, ITEM_INCLUDED_YES = 2 };

enum {
    // Successful responses
    SUCCESS = 0x9000,

    // Start of error which trigger automatic response
    // Note that any such error will reset
    // multi-APDU exchange
    _ERR_AUTORESPOND_START = 0x6E00,

    // Bad request header
    ERR_MALFORMED_REQUEST_HEADER = 0x6E01,
    // Unknown CLA
    ERR_BAD_CLA = 0x6E02,
    // Unknown INS
    ERR_UNKNOWN_INS = 0x6E03,
    // attempt to change INS while the current call was not finished
    ERR_STILL_IN_CALL = 0x6E04,
    // P1 or P2 is invalid
    ERR_INVALID_REQUEST_PARAMETERS = 0x6E05,
    // Request is not valid in the context of previous calls
    ERR_INVALID_STATE = 0x6E06,
    // Some part of request data is invalid (or unknown to this app)
    // (includes not enough data and too much data)
    ERR_INVALID_DATA = 0x6E07,
    // previously used for rejected BIP44 paths, now we use ERR_REJECTED_BY_POLICY
    // ERR_INVALID_BIP44_PATH         = 0x6E08,

    // User rejected the action
    ERR_REJECTED_BY_USER = 0x6E09,
    // Ledger security policy rejected the action
    ERR_REJECTED_BY_POLICY = 0x6E10,

    // Pin screen
    ERR_DEVICE_LOCKED = 0x6E11,

    // previously used for unsupported Shelley address types
    // ERR_UNSUPPORTED_ADDRESS_TYPE   = 0x6E12,

    // end of errors which trigger automatic response
    _ERR_AUTORESPOND_END = 0x6E13,

    // Errors below SHOULD NOT be returned to the client
    // Instead, leaking these to the main() scope
    // means unexpected programming error
    // and we should stop further processing
    // to avoid exploits

    // Internal errors
    ERR_ASSERT = 0x4700,
    ERR_NOT_IMPLEMENTED = 0x4701,

    // stream
    ERR_NOT_ENOUGH_INPUT = 0x4710,
    ERR_DATA_TOO_LARGE = 0x4711,

    // cbor
    ERR_UNEXPECTED_TOKEN = 0x4720,
};

bool device_is_unlocked();

// Normal code should use just this helper function
void io_send_buf(uint16_t code, uint8_t* buffer, size_t tx);
