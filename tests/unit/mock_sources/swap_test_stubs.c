/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>

#include "app_context.h"
#include "cardano_swo.h"
#include "ledger_assert.h"
#include "swap.h"
#include "swap_lib.h"
#include "tx_output_types.h"

volatile bool G_called_from_swap = false;
volatile bool G_swap_response_ready = false;
volatile uint8_t *G_swap_signing_return_value_address = NULL;
bool G_swap_signing_started = false;

unsigned int g_swap_stub_fee_check_calls = 0;
unsigned int g_swap_stub_destination_check_calls = 0;
unsigned int g_swap_stub_amount_check_calls = 0;
uint16_t g_swap_reject_common_error_code = 0;
uint8_t g_swap_reject_app_error_code = 0;

jmp_buf *g_swap_reject_jmp_buf = NULL;
jmp_buf *g_swap_os_lib_end_jmp_buf = NULL;

static bool g_swap_stub_initialized = false;
static bool g_swap_stub_fee_ok = true;
static bool g_swap_stub_destination_ok = true;
static bool g_swap_stub_amount_ok = true;

void swap_test_stubs_reset(void) {
    G_called_from_swap = false;
    G_swap_response_ready = false;
    G_swap_signing_return_value_address = NULL;
    G_swap_signing_started = false;

    g_swap_stub_fee_check_calls = 0;
    g_swap_stub_destination_check_calls = 0;
    g_swap_stub_amount_check_calls = 0;
    g_swap_reject_common_error_code = 0;
    g_swap_reject_app_error_code = 0;

    g_swap_stub_initialized = false;
    g_swap_stub_fee_ok = true;
    g_swap_stub_destination_ok = true;
    g_swap_stub_amount_ok = true;
    g_swap_reject_jmp_buf = NULL;
    g_swap_os_lib_end_jmp_buf = NULL;
}

void swap_test_stubs_set_initialized(bool initialized) {
    g_swap_stub_initialized = initialized;
}

void swap_test_stubs_set_validation_results(bool fee_ok, bool destination_ok, bool amount_ok) {
    g_swap_stub_fee_ok = fee_ok;
    g_swap_stub_destination_ok = destination_ok;
    g_swap_stub_amount_ok = amount_ok;
}

void swap_test_stubs_set_reject_jmp_buf(jmp_buf *jmp_buffer) {
    g_swap_reject_jmp_buf = jmp_buffer;
}

void swap_test_stubs_set_os_lib_end_jmp_buf(jmp_buf *jmp_buffer) {
    g_swap_os_lib_end_jmp_buf = jmp_buffer;
}

bool swap_transaction_params_initialized(void) {
    return g_swap_stub_initialized;
}

bool swap_copy_transaction_parameters(create_transaction_parameters_t *params) {
    (void) params;
    g_swap_stub_initialized = true;
    return true;
}

bool swap_check_destination_validity(const tx_output_destination_t *destination) {
    (void) destination;
    g_swap_stub_destination_check_calls++;
    return g_swap_stub_destination_ok;
}

bool swap_check_amount_validity(uint64_t amount) {
    (void) amount;
    g_swap_stub_amount_check_calls++;
    return g_swap_stub_amount_ok;
}

bool swap_check_fee_validity(uint64_t fee) {
    (void) fee;
    g_swap_stub_fee_check_calls++;
    return g_swap_stub_fee_ok;
}

__attribute__((noreturn)) void swap_reject_and_exit(uint8_t common_error_code,
                                                    uint8_t application_specific_error_code) {
    g_swap_reject_common_error_code = common_error_code;
    g_swap_reject_app_error_code = application_specific_error_code;
    apdu_response_send_sw(SWO_COMMAND_NOT_ALLOWED);
    if (g_swap_reject_jmp_buf != NULL) {
        longjmp(*g_swap_reject_jmp_buf, 1);
    }
    LEDGER_ASSERT(false,
                  "Unexpected swap_reject_and_exit in unit test: common=%u app=%u",
                  (unsigned int) common_error_code,
                  (unsigned int) application_specific_error_code);
    for (;;) {
    }
}
