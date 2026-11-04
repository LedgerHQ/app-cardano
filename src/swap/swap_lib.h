/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#ifdef HAVE_SWAP

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "swap.h"
#include "tx_output_types.h"

// App-specific error codes for swap detail byte
#define SWAP_APP_CODE_DEFAULT               0x00
#define SWAP_APP_CODE_BAD_INS               0x01
#define SWAP_APP_CODE_MULTI_SIGN            0x02
#define SWAP_APP_CODE_DENIED_WITNESS_POLICY 0x03

// Status word returned for swap validation failures
#define SWO_SWAP_CHECKING_FAIL 0x6001

/**
 * Save the data validated during the Exchange app flow.
 * Called by the SDK when the Exchange app sends CREATE_TRANSACTION_PARAMETERS.
 *
 * Important: Must copy params to stack first, then zero BSS, then copy to global.
 * This is because params may overlap with global BSS memory when called as a library.
 */
bool swap_copy_transaction_parameters(create_transaction_parameters_t *params);

/**
 * Check that a transaction output destination matches the swap-validated destination.
 * Only DESTINATION_THIRD_PARTY outputs are checked against the swap destination.
 *
 * @param destination  The output destination to validate
 * @return true if destination matches, false otherwise
 */
bool swap_check_destination_validity(const tx_output_destination_t *destination);

/**
 * Check that a transaction output amount matches the swap-validated amount.
 *
 * @param amount  The output amount in lovelace
 * @return true if amount matches, false otherwise
 */
bool swap_check_amount_validity(uint64_t amount);

/**
 * Check that the transaction fee matches the swap-validated fee.
 *
 * @param fee  The transaction fee in lovelace
 * @return true if fee matches, false otherwise
 */
bool swap_check_fee_validity(uint64_t fee);

/**
 * Returns true only when swap parameters were copied from Exchange and validated.
 */
bool swap_transaction_params_initialized(void);

/**
 * Latch marking that a swap transaction signing has begun (the single-transaction swap
 * authorization has been consumed). Set on the first SIGN_TX INIT in swap mode.
 *
 * It lives in BSS and is zeroed once per authenticated swap by swap_copy_transaction_parameters()
 * (os_explicit_zero_BSS_segment). It deliberately survives reset_app_context(), which only clears
 * G_context, so a recoverable reset after releasing a non-final witness cannot be used to start a
 * second transaction under the same Exchange approval. Must never be cleared by
 * reset_app_context().
 */
extern bool G_swap_signing_started;

/**
 * Send a swap error and terminate processing.
 *
 * This wrapper keeps call-sites explicit about non-returning behavior even if
 * SDK annotations ever regress.
 */
__attribute__((noreturn)) void swap_reject_and_exit(uint8_t common_error_code,
                                                    uint8_t application_specific_error_code);

#endif  // HAVE_SWAP
