/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "addressUtilsShelley.h"
#include "app_context.h"
#include "bech32.h"
#include "cardano_swo.h"
#include "cvote_hash.h"
#include "format.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "io.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "securityPolicy.h"
#include "sign_tx_aux_data.h"
#include "tx_output_types.h"
#include "tx_utils.h"
#include "ui_constants.h"
#include "ui_display_cvote_aux_data.h"
#include "ui_formatters.h"
#include "ui_icons.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "utils.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace UI flow details.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[ui_cvote_aux_data] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

// Each delegation uses 3 UI pairs (index, key, weight), plus one optional warning pair.
#define CVOTE_DELEGATION_UI_PAIRS         3
#define CVOTE_DELEGATION_WARNING_UI_PAIRS 1
#define CVOTE_DELEGATION_UI_PAIRS_MAX \
    (CVOTE_DELEGATION_UI_PAIRS + CVOTE_DELEGATION_WARNING_UI_PAIRS)
#define CVOTE_REGISTRATIONS_UI_PAIRS       1
#define CVOTE_VOTE_KEY_UI_PAIRS            1
#define CVOTE_STAKING_KEY_UI_PAIRS         1
#define CVOTE_PAYMENT_DESTINATION_UI_PAIRS 1
#define CVOTE_NONCE_UI_PAIRS               1
#define CVOTE_VOTING_PURPOSE_UI_PAIRS      1
#define CVOTE_AUX_DATA_HASH_UI_PAIRS       1

static const char cvote_review_title[] = "Review vote delegation";

// Helper to check if this is the last streaming page
static inline bool cvote_is_last_chunk(const cvote_aux_data_t *aux_data) {
    uint16_t remaining = aux_data->ui_delegations_total - aux_data->ui_delegations_shown;
    return (remaining == 0);
}

static void cvote_add_vote_key_path_warning_pair(void) {
    UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"), UI_STATIC_LABEL("UNUSUAL key derivation path"));
}

static void cvote_finalize_pairs_count_for_display(void) {
    ASSERT(g_pairsList != NULL);
    uint16_t actual_pair_count = ui_pairs_get_count();
    LEDGER_ASSERT(actual_pair_count <= UINT8_MAX, "UI pair count overflow");
    g_pairsList->nbPairs = (uint8_t) actual_pair_count;
}

static void cvote_aux_data_review_cleanup(void) {
    ui_all_cleanup();
}

static void cvote_aux_data_review_choice(bool confirm) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION, "bad state");
    LEDGER_ASSERT(tx_aux_data_ctx()->cvote_aux_data.state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED,
                  "bad state");

    // CLEANUP
    cvote_aux_data_review_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE_MODULE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed");
    nbgl_useCaseSpinner("Processing");
    finalize_sign_tx_aux_data();
}

static void cvote_aux_data_streaming_continue_choice(bool confirm) {
    cvote_aux_data_t *aux_data = &tx_aux_data_ctx()->cvote_aux_data;
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION, "bad state");
    LEDGER_ASSERT(aux_data->ui_streaming.on, "bad state");
    LEDGER_ASSERT(aux_data->ui_streaming.review_started, "bad state");
    LEDGER_ASSERT(aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS ||
                      aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED,
                  "bad state");

    ui_free_pairs();

    if (!confirm) {
        TRACE_MODULE("User rejected");
        ui_free_warnings();
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed");
    if (cvote_is_last_chunk(aux_data)) {
        nbgl_useCaseReviewStreamingFinish("Confirm vote delegation", cvote_aux_data_review_choice);
        return;
    }

    apdu_response_send_sw(SWO_SUCCESS);
}

static void cvote_streaming_display_current_page(void) {
    cvote_finalize_pairs_count_for_display();
    nbgl_useCaseReviewStreamingContinue(g_pairsList, cvote_aux_data_streaming_continue_choice);
}

// The first data page must be displayed only from here; displaying it earlier
// would replace the start screen and its warnings before the user sees them.
static void cvote_aux_data_streaming_start_choice(bool confirm) {
    cvote_aux_data_t *aux_data = &tx_aux_data_ctx()->cvote_aux_data;
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION, "bad state");
    LEDGER_ASSERT(aux_data->ui_streaming.on, "bad state");
    LEDGER_ASSERT(aux_data->ui_streaming.review_started, "bad state");
    LEDGER_ASSERT(aux_data->state == CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE, "bad state");

    if (!confirm) {
        TRACE_MODULE("User rejected on streaming start screen");
        cvote_aux_data_review_cleanup();
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed streaming start screen");
    // Initial page is now ready; next APDU accepted by the state machine is delegation.
    aux_data->state = CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS;
    cvote_streaming_display_current_page();
}

static bool cvote_start_streaming_review(cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL);
    LEDGER_ASSERT(!aux_data->ui_streaming.review_started, "Streaming review already started");

    LEDGER_ASSERT(warning_bits_except_mask(tx_aux_data_ctx()->cvote_warning_bits,
                                           CVOTE_AUX_DATA_WARNING_BITS_MASK) == 0,
                  "Transaction warnings leaked into CVote warning bits - cvote_warning_bits should "
                  "only contain CVote AUX_DATA warnings");

    // Build warnings known at start of streaming flow.
    // Warnings for specific delegations are added via cvote_add_vote_key_path_warning_pair.
    ui_status_t warning_status = ui_build_warnings(tx_aux_data_ctx()->cvote_warning_bits);
    if (warning_status != UI_STATUS_SUCCESS) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);  // LCOV_EXCL_LINE
        return false;                                 // LCOV_EXCL_LINE
    }

    const nbgl_warning_t *warning_ptr = ui_get_warnings();
    aux_data->ui_streaming.review_started = true;
    nbgl_useCaseAdvancedReviewStreamingStart(TYPE_OPERATION,
                                             &ICON_APP_CARDANO,
                                             cvote_review_title,
                                             NULL,
                                             warning_ptr,
                                             cvote_aux_data_streaming_start_choice);

    return true;
}

static bool format_cvote_delegation_index(uint16_t delegation_index, char *out, size_t out_size) {
    ASSERT(out != NULL);
    int written = snprintf(out, out_size, "#%u", delegation_index);
    return (written > 0) && ((size_t) written + 1 < out_size);
}

static bool format_cvote_reward_address(const tx_output_destination_t *destination,
                                        uint8_t network_id,
                                        char *out,
                                        size_t out_size) {
    (void) network_id;

    return format_tx_output_destination_human_readable(destination, out, out_size);
}

static void cvote_add_vote_key_pair(const char *label,
                                    const cvote_credential_t *credential,
                                    warning_bits_t vote_key_warnings) {
    ASSERT(label != NULL);
    ASSERT(credential != NULL);
    LEDGER_ASSERT(warning_bits_except_mask(
                      vote_key_warnings,
                      warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                  "Unexpected vote-key warning bits");

    switch (credential->type) {
        case CVOTE_CREDENTIAL_KEY_PATH:
            if (warning_bits_has(vote_key_warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) {
                cvote_add_vote_key_path_warning_pair();
            }
            UI_ADD_FORMAT1(label,
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &credential->keyPath);
            break;
        case CVOTE_CREDENTIAL_KEY:
            UI_ADD_FORMAT3(label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "cvote_vk",
                           credential->publicKey,
                           PUBLIC_KEY_LENGTH);
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unexpected vote credential type");
            break;
            // LCOV_EXCL_STOP
    }
}

static uint16_t cvote_initial_pairs_count(const cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL);

    uint16_t pair_count = CVOTE_REGISTRATIONS_UI_PAIRS;

    if (aux_data->ui_show.vote_key) {
        warning_bits_t vote_key_warnings = 0;
        security_policy_t vote_key_policy =
            policyForCVoteRegistrationVoteKey(&aux_data->vote_credential,
                                              aux_data->format,
                                              &vote_key_warnings);
        LEDGER_ASSERT(warning_bits_except_mask(
                          vote_key_warnings,
                          warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                      "Unexpected vote-key warning bits");
        LEDGER_ASSERT(vote_key_policy == POLICY_SHOW, "Vote key policy changed before UI");

        pair_count += warning_bits_has(vote_key_warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)
                          ? CVOTE_DELEGATION_WARNING_UI_PAIRS
                          : 0;
        pair_count += CVOTE_VOTE_KEY_UI_PAIRS;
    }
    if (aux_data->ui_show.staking_key) {
        pair_count += CVOTE_STAKING_KEY_UI_PAIRS;
    }
    if (aux_data->ui_show.payment_destination) {
        pair_count += CVOTE_PAYMENT_DESTINATION_UI_PAIRS;
    }
    if (aux_data->ui_show.nonce) {
        pair_count += CVOTE_NONCE_UI_PAIRS;
    }
    if (aux_data->ui_show.voting_purpose && aux_data->format == CIP36) {
        pair_count += CVOTE_VOTING_PURPOSE_UI_PAIRS;
    }

    return pair_count;
}

static uint32_t cvote_total_pairs_count(const cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL);
    return (uint32_t) cvote_initial_pairs_count(aux_data) +
           ((uint32_t) aux_data->remaining_delegations * (uint32_t) CVOTE_DELEGATION_UI_PAIRS_MAX);
}

static bool cvote_add_initial_pairs(cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL);
    ui_render_session_t session = {0};
    ui_render_scope_begin(&session);

    START_COUNT();
    if (aux_data->ui_show.vote_key) {
        warning_bits_t vote_key_warnings = 0;
        security_policy_t vote_key_policy =
            policyForCVoteRegistrationVoteKey(&aux_data->vote_credential,
                                              aux_data->format,
                                              &vote_key_warnings);
        LEDGER_ASSERT(warning_bits_except_mask(
                          vote_key_warnings,
                          warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                      "Unexpected vote-key warning bits");
        LEDGER_ASSERT(vote_key_policy == POLICY_SHOW, "Vote key policy changed before UI");
        cvote_add_vote_key_pair(UI_STATIC_LABEL("Vote key"),
                                &aux_data->vote_credential,
                                vote_key_warnings);
    }

    if (aux_data->ui_show.staking_key) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Staking key"),
                       MAX_BIP44_PATH_STRING_LENGTH,
                       format_bip44_path,
                       &aux_data->staking_credential.keyPath);
    }

    if (aux_data->ui_show.payment_destination) {
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Rewards go to"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_cvote_reward_address,
                       &aux_data->destination,
                       G_context.tx_info.tx_params.networkId);
    }

    if (aux_data->ui_show.nonce) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Nonce"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       aux_data->nonce);
    }

    if (aux_data->ui_show.voting_purpose && aux_data->format == CIP36) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Voting purpose"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       aux_data->voting_purpose);
    }

    UI_ADD_FORMAT1(UI_STATIC_LABEL("Delegations"),
                   MAX_UINT16_STRING_LENGTH,
                   format_uint16,
                   aux_data->ui_delegations_total);

    CHECK_COUNT(cvote_initial_pairs_count(aux_data));
    return (ui_render_scope_end() == UI_STATUS_SUCCESS);
}

// Returns true on success, false if delegation was denied (error already sent).
static void cvote_add_delegation_pairs(cvote_aux_data_t *aux_data,
                                       const cvote_credential_t *credential,
                                       uint32_t weight) {
    ASSERT(credential != NULL);
    ASSERT(aux_data != NULL && aux_data->ui_delegations_shown < aux_data->ui_delegations_total);

    // Evaluate policy before opening the render scope so we know the exact pair
    // count — required for the streaming path, which calls ui_pairs_init here.
    warning_bits_t vote_key_warnings = 0;
    security_policy_t delegation_policy =
        policyForCVoteRegistrationVoteKey(credential, aux_data->format, &vote_key_warnings);
    LEDGER_ASSERT(warning_bits_except_mask(
                      vote_key_warnings,
                      warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                  "Unexpected vote-key warning bits");

    LEDGER_ASSERT(delegation_policy != POLICY_DENY, "CVote delegation policy denied");

    // In streaming mode, allocate exactly the pairs this delegation will use.
    // In non-streaming mode, ui_pairs_init was already called once upfront.
    if (aux_data->ui_streaming.on) {
        LEDGER_ASSERT(aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS ||
                          aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED,
                      "Streaming delegation page in wrong state: %d",
                      aux_data->state);
        uint16_t pair_count =
            (delegation_policy == POLICY_SHOW)
                ? (uint16_t) (CVOTE_DELEGATION_UI_PAIRS +
                              (warning_bits_has(vote_key_warnings,
                                                WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)
                                   ? CVOTE_DELEGATION_WARNING_UI_PAIRS
                                   : 0))
                : 0;
        TRACE_MODULE("CVote streaming page: shown=%u/%u, pair_count=%u, max_pairs=%u, is_last=%d",
                     aux_data->ui_delegations_shown,
                     aux_data->ui_delegations_total,
                     pair_count,
                     MAX_UI_PAIRS,
                     cvote_is_last_chunk(aux_data));
        // This is a small per-delegation allocation; failure indicates a bug.
        LEDGER_ASSERT(ui_pairs_init(pair_count),
                      "ui_pairs_init failed for streaming delegation page");
    }

    aux_data->ui_delegations_shown++;

    ui_render_session_t session = {0};
    ui_render_scope_begin(&session);

    switch (delegation_policy) {
        case POLICY_SHOW: {
            uint16_t expected_pairs =
                CVOTE_DELEGATION_UI_PAIRS +
                (warning_bits_has(vote_key_warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)
                     ? CVOTE_DELEGATION_WARNING_UI_PAIRS
                     : 0);
            START_COUNT();
            ui_pairs_force_new_page();
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Delegation"),
                           MAX_DELEGATION_INDEX_STRING_LENGTH,
                           format_cvote_delegation_index,
                           aux_data->ui_delegations_shown);
            cvote_add_vote_key_pair(UI_STATIC_LABEL("Key"), credential, vote_key_warnings);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Weight"),
                           MAX_UINT64_STRING_LENGTH,
                           format_uint64,
                           weight);
            CHECK_COUNT(expected_pairs);
            break;
        }
        // LCOV_EXCL_START
        case POLICY_HIDE:
            // could be legitimate, but not under current security policies, untested
            LEDGER_ASSERT(false, "unsupported security policy");
            break;
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    ui_status_t result = ui_render_scope_end();
    ASSERT(result == UI_STATUS_SUCCESS);
}

bool ui_cvote_aux_data_init_non_streaming(cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL && !aux_data->ui_streaming.on);
    ASSERT(aux_data != NULL && (aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS ||
                                aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED));

    uint32_t total_pair_count_u32 = cvote_total_pairs_count(aux_data);
    LEDGER_ASSERT(total_pair_count_u32 <= MAX_UI_PAIRS,
                  "Non-streaming pair count exceeds max: %u",
                  (unsigned) total_pair_count_u32);
    ASSERT(total_pair_count_u32 <= UINT16_MAX);
    uint16_t total_pair_count = (uint16_t) total_pair_count_u32;

    if (!ui_pairs_init(total_pair_count)) {
        TRACE_MODULE("CVote UI: failed to initialize pairs");
        return false;  // LCOV_EXCL_LINE
    }

    if (!cvote_add_initial_pairs(aux_data)) {
        TRACE_MODULE("CVote UI: failed to add initial pairs");
        return false;  // LCOV_EXCL_LINE
    }

    return true;
}

void ui_cvote_aux_data_init_vars(cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL && (aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED ||
                                aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS ||
                                aux_data->state == CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE));

    // Initialize UI delegation tracking
    aux_data->ui_delegations_total = aux_data->remaining_delegations;
    aux_data->ui_delegations_shown = 0;

    // Initialize streaming state (all fields zeroed)
    explicit_bzero(&aux_data->ui_streaming, sizeof(aux_data->ui_streaming));

    // Determine if streaming is forced: too many UI pairs
    uint32_t total_pair_count = cvote_total_pairs_count(aux_data);
    aux_data->ui_streaming.on = (total_pair_count > MAX_UI_PAIRS);
}

void ui_cvote_aux_data_streaming_show_initial_page(cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL && aux_data->ui_streaming.on);
    ASSERT(aux_data != NULL && aux_data->state == CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE);

    uint16_t initial_pairs = cvote_initial_pairs_count(aux_data);
    ASSERT(initial_pairs > 0);

    TRACE_MODULE("CVote streaming initial page: initial_pairs=%u, max_pairs=%u",
                 initial_pairs,
                 MAX_UI_PAIRS);

    if (!ui_pairs_init(initial_pairs)) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);  // LCOV_EXCL_LINE
        return;                                       // LCOV_EXCL_LINE
    }

    if (!cvote_add_initial_pairs(aux_data)) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);  // LCOV_EXCL_LINE
        return;                                       // LCOV_EXCL_LINE
    }

    LEDGER_ASSERT(!aux_data->ui_streaming.review_started,
                  "Streaming review should start exactly once from initial page");
    // The initial page is displayed from cvote_aux_data_streaming_start_choice.
    if (!cvote_start_streaming_review(aux_data)) {
        return;  // LCOV_EXCL_LINE
    }
}

void ui_cvote_aux_data_add_delegation(cvote_aux_data_t *aux_data,
                                      const cvote_credential_t *credential,
                                      uint32_t weight) {
    ASSERT(aux_data != NULL);
    ASSERT(credential != NULL);

    cvote_add_delegation_pairs(aux_data, credential, weight);

    if (aux_data->ui_streaming.on) {
        // Display this delegation immediately.
        cvote_streaming_display_current_page();
    }
}

void ui_cvote_aux_data_show_non_streaming_final_review(cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL && aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED);
    ASSERT(aux_data != NULL && !aux_data->ui_streaming.on);

    LEDGER_ASSERT(warning_bits_except_mask(tx_aux_data_ctx()->cvote_warning_bits,
                                           CVOTE_AUX_DATA_WARNING_BITS_MASK) == 0,
                  "Transaction warnings leaked into CVote warning bits - cvote_warning_bits should "
                  "only contain CVote AUX_DATA warnings");

    // Build CVote-specific warnings for display
    ui_status_t warning_status = ui_build_warnings(tx_aux_data_ctx()->cvote_warning_bits);
    if (warning_status != UI_STATUS_SUCCESS) {
        cvote_aux_data_review_cleanup();              // LCOV_EXCL_LINE
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);  // LCOV_EXCL_LINE
        return;                                       // LCOV_EXCL_LINE
    }

    const nbgl_warning_t *warningPtr = ui_get_warnings();
    cvote_finalize_pairs_count_for_display();
    nbgl_useCaseAdvancedReview(TYPE_OPERATION,
                               g_pairsList,
                               &ICON_APP_CARDANO,
                               cvote_review_title,
                               NULL,
                               "Confirm vote delegation",
                               NULL,
                               warningPtr,
                               cvote_aux_data_review_choice);
}
