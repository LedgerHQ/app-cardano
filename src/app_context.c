/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <string.h>  // explicit_bzero

#include "globals.h"
#include "app_context.h"
#include "utils.h"
#include "mem.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "tx_utils.h"
#include "io.h"

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_error_code_helpers.h"
#include "swap_lib.h"
#endif

typedef struct {
    bool response_sent;
    bool response_deferred_to_ux;
    command_e instruction;
} apdu_response_state_t;

static apdu_response_state_t G_apdu_response_state = {0};

static void apdu_response_state_reset(void) {
    explicit_bzero(&G_apdu_response_state, SIZEOF(G_apdu_response_state));
    G_apdu_response_state.instruction = INS_NONE;
}

void apdu_response_state_force_reset(void) {
    apdu_response_state_reset();
}

void apdu_response_begin(command_e instruction) {
    // Deferred APDUs are completed in two steps:
    // 1) handler marks "deferred" (response will be sent from UX callback),
    // 2) UX callback later sends the response ("sent").
    // If that prior async APDU already reached this completed state, clear it now
    // before tracking a new APDU.
    if (G_apdu_response_state.response_sent && G_apdu_response_state.response_deferred_to_ux) {
        apdu_response_state_reset();
    }

    ASSERT(!G_apdu_response_state.response_sent && !G_apdu_response_state.response_deferred_to_ux);

    G_apdu_response_state.response_sent = false;
    G_apdu_response_state.response_deferred_to_ux = false;
    G_apdu_response_state.instruction = instruction;
}

void apdu_response_deferred(void) {
    ASSERT(!G_apdu_response_state.response_sent);

    G_apdu_response_state.response_deferred_to_ux = true;
}

void apdu_response_finalize_after_handler(void) {
    ASSERT(G_apdu_response_state.response_sent || G_apdu_response_state.response_deferred_to_ux);

    if (G_apdu_response_state.response_sent) {
        apdu_response_state_reset();
    }
}

void apdu_response_send_sw(uint16_t swo) {
    ASSERT(!G_apdu_response_state.response_sent);
    G_apdu_response_state.response_sent = true;

    int io_send_result = io_send_sw(swo);
    ASSERT(io_send_result >= 0);
}

void apdu_response_send_data(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    ASSERT(!G_apdu_response_state.response_sent);
    G_apdu_response_state.response_sent = true;

    int io_send_result = io_send_response_pointer(buffer, bufferLength, swo);
    ASSERT(io_send_result >= 0);
}

bool apdu_response_was_sent(void) {
    return G_apdu_response_state.response_sent;
}

bool apdu_response_is_pending_ux(void) {
    return !G_apdu_response_state.response_sent && G_apdu_response_state.response_deferred_to_ux;
}

/**
 * Free request-scoped heap buffers owned by G_context before the heap is reset.
 *
 * reset_app_context() reclaims all transient memory in bulk via mem_utils_reset_app_heap(). That
 * bulk reset does not emit per-allocation free events, so the memory profiler would otherwise flag
 * any still-live context buffer as a leak on deny / parse-error paths (the happy path frees them
 * explicitly). The context is the owner of last resort for these buffers, so freeing them here
 * keeps the profiler accurate on every terminal path that routes through send_swo_and_reset().
 *
 * Buffers are accessed via their union members directly (not the tx_*_ctx() accessors, which assert
 * a specific state) under explicit req_type/state guards. APP_MEM_FREE_AND_NULL is idempotent, so
 * double-coverage with the happy-path frees (e.g. finalize_sign_tx / finalize_sign_msg) is safe.
 */
static void free_request_context_buffers(void) {
    switch (G_context.req_type) {
        case REQUEST_SIGN_TRANSACTION:
            switch (G_context.state.tx_state) {
                case TX_STATE_AUX_DATA:
                    APP_MEM_FREE_AND_NULL(
                        (void **) &G_context.tx_info.aux_data.raw_cvote_init_data);
                    break;
                case TX_STATE_CHUNKS:
                case TX_STATE_RECEIVED:
                case TX_STATE_HASHED:
                case TX_STATE_UI_REVIEW:
                    APP_MEM_FREE_AND_NULL((void **) &G_context.tx_info.body.raw_tx);
                    break;
                default:
                    break;
            }
            break;
        case REQUEST_SIGN_MSG:
            APP_MEM_FREE_AND_NULL((void **) &G_context.sign_msg_info.msgBuffer);
            APP_MEM_FREE_AND_NULL((void **) &G_context.sign_msg_info.sigStructureBuffer);
            break;
        default:
            break;
    }
}

void reset_app_context(void) {
    ui_all_cleanup();

    // Free request-scoped heap buffers explicitly so the memory profiler observes per-allocation
    // free events, before the bulk heap reset below reclaims everything at once.
    free_request_context_buffers();

    // Free any transaction-parsing temp buffers still live at an abort (parse error / policy DENY),
    // for the same reason. No-op on the happy path. Must run before the bulk heap reset.
    tx_free_all_temp_buffers();

    // Reset the SDK allocator to wipe all transient memory
    ASSERT(mem_utils_reset_app_heap());

    // Securely zero out the entire global context
    explicit_bzero(&G_context, sizeof(G_context));

    // Ensure request type is explicitly idle
    G_context.req_type = REQUEST_NONE;

    // Fix up APDU response state for the next command:
    //
    //   sent=false, deferred=false  normal idle state, nothing to do
    //   sent=true,  deferred=false  response sent; apdu_response_finalize_after_handler()
    //                               will acknowledge it
    //   sent=true,  deferred=true   response sent; as above
    //   sent=false, deferred=true   stale: some failure occurred between
    //                               apdu_response_deferred() and the UX callback;
    //                               calling reset_app_context() was the proper way to do.
    //                               Force sent=true so apdu_response_begin() treats
    //                               it as a completed deferred response and clears it.
    if (!G_apdu_response_state.response_sent && G_apdu_response_state.response_deferred_to_ux) {
        G_apdu_response_state.response_sent = true;
    }

    if (!G_apdu_response_state.response_sent && !G_apdu_response_state.response_deferred_to_ux) {
        G_apdu_response_state.instruction = INS_NONE;
    }
}

void send_swo_and_reset(uint16_t swo) {
    TRACE("swo=0x%04x", swo);
#ifdef HAVE_SWAP
    // Once swap signing has started, an error ends the swap and gives control back to Exchange.
    // swap_reject_and_exit() never returns, so the status word below is not sent in this case.
    if (G_called_from_swap && G_swap_signing_started) {
        swap_reject_and_exit(SWAP_EC_ERROR_GENERIC, SWAP_APP_CODE_DEFAULT);
    }
#endif
    apdu_response_send_sw(swo);
    reset_app_context();
}
