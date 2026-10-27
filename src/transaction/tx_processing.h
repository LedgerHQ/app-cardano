/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Public interface for transaction processing (policy enforcement, UI, hashing).
 * Implementation is in tx_processing.c, tx_processing_outputs.c, and
 * tx_processing_certificates.c.
 */

#pragma once

#include "buffer.h"

#include "cardano_swo.h"
#include "securityPolicyType.h"
#include "tx.h"
#include "tx_hash_builder.h"
#include "tx_ui_pair_counts.h"
#include "securityWarnings.h"
#include "cbor_canonical.h"

typedef struct {
    bool run_validation;    // validation run: true, UI render run: true
    bool run_hash_builder;  // validation run: true, UI render run: false
    bool ui_count_pairs;    // validation run: true, UI render run: false
    bool ui_render;         // validation run: false, UI render run: true
} tx_processing_mode_t;

typedef enum {
    TX_UI_REVIEW_MODE_NONE = 0,
    TX_UI_REVIEW_MODE_PENDING_BLIND_SIGNING_CHOICE = 1,
    TX_UI_REVIEW_MODE_DETAILS = 2,
    TX_UI_REVIEW_MODE_HASH_ONLY = 3,
} tx_ui_review_mode_e;

// Standard policy dispatch: deny → reject tx, show → call render_fn, hide → skip.
// Requires render_fn to accept (mode, ...) where mode is const tx_processing_mode_t *.
// Only suitable when SHOW and HIDE branches have no extra logic beyond the UI call.
//
// WARNING: POLICY_DENY causes an immediate `return false` in the *calling function*.
// This is intentional — denial must abort transaction processing unconditionally.
// Callers do not need to check a return value; the function terminates on DENY.
#define APPLY_POLICY(policy, render_fn, mode, ...)                        \
    do {                                                                  \
        switch (policy) {                                                 \
            case POLICY_DENY:                                             \
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED); \
                return false;                                             \
            case POLICY_SHOW:                                             \
                render_fn(mode, ##__VA_ARGS__);                           \
                break;                                                    \
            case POLICY_HIDE:                                             \
                break;                                                    \
            /* LCOV_EXCL_START */                                         \
            default:                                                      \
                LEDGER_ASSERT(false, "Unknown policy");                   \
                break;                                                    \
                /* LCOV_EXCL_STOP */                                      \
        }                                                                 \
    } while (0)

/**
 * Mutable processing state for one run over the transaction body.
 * Stored in global tx context (not on the stack) due to hash_builder size.
 * Initialized by tx_processing_setup_state() at the start of each run.
 */
typedef struct {
    const tx_params_t *tx_params;  // points to global tx params
    tx_processing_mode_t mode;     // per-run processing mode
    warning_bits_t *warning_bits;  // points to global warnings or local dummy

    tx_hash_builder_t hash_builder;

    uint16_t swap_third_party_output_count;
    // an output's payload is too large to show in full (inline datum or reference script)
    bool output_payload_exceeds_display;
} tx_processing_state_t;

// ---------------------------------------------------------------------------
// Canonical ordering macros (tx_processing layer — error-reporting wrappers)
// ---------------------------------------------------------------------------

/**
 * Declare a canonical ordering tracker in the current scope.
 * Must appear before any ENFORCE_CANONICAL_ORDERING_CHECK using the same name.
 */
#define ENFORCE_CANONICAL_ORDERING_START(tracker_name) CBOR_CANONICAL_START(tracker_name)

/**
 * Check that next_key maintains canonical ordering relative to the previous key
 * seen by tracker_name. On failure, calls tx_handle_parse_error(error_swo) and
 * returns false from the enclosing function.
 */
#define ENFORCE_CANONICAL_ORDERING_CHECK(tracker_name, next_key, next_key_length, error_swo) \
    do {                                                                                     \
        if (!CBOR_CANONICAL_CHECK(tracker_name, next_key, next_key_length)) {                \
            tx_handle_parse_error(error_swo);                                                \
            return false;                                                                    \
        }                                                                                    \
    } while (0)

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

bool tx_validate(void);
bool tx_render_ui_chunk(uint16_t from);
bool tx_render_ui(tx_ui_review_mode_e review_mode);
void tx_handle_parse_error(uint16_t swo);
