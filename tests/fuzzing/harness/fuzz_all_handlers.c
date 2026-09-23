#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dispatcher.h"
#include "fuzz_utils.h"
#include "app_context.h"
#include "apdu/dispatcher.h"

/**
 * Unified fuzzing harness for all APDU commands.
 *
 * This harness feeds a continuous stream of random APDU commands to the dispatcher,
 * testing the command routing logic, state machine transitions, and handler dispatch.
 * It simulates real device behavior where multiple commands may be sent in sequence.
 *
 * APDU format:
 *   CLA = 0xD7 (Cardano app)
 *   INS = any valid instruction
 *   P1  = varies by instruction
 *   P2  = varies by instruction
 *   LC  = variable length
 *   DATA = instruction-specific data
 *
 * Supported instructions:
 *   - 0x00: GET_SERIAL
 *   - 0x01: GET_VERSION
 *   - 0x02: GET_PUBLIC_KEY
 *   - 0x03: SIGN_TX
 *   - 0x08: SIGN_OPCERT
 *   - 0x04: SIGN_MSG (if supported)
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (sigsetjmp(fuzz_exit_jump_ctx.jmp_buf, 1)) return 0;
    fuzzing_reset_state();
    static const uint8_t dummy = 0;

    // Process the fuzzing input as a stream of consecutive APDU commands
    // Continue processing until we run out of data
    while (size >= 5) {
        // Parse APDU header
        command_t cmd = {0};
        cmd.cla = data[0];
        cmd.ins = data[1];
        cmd.p1 = data[2];
        cmd.p2 = data[3];
        cmd.lc = data[4];

        // Advance past header
        data += 5;
        size -= 5;

        // Check if we have enough data for the payload
        if (size < cmd.lc) {
            // Not enough data for this command, stop processing
            break;
        }

        // Copy command data
        uint8_t *cmd_data = NULL;
        if (cmd.lc > 0) {
            cmd_data = malloc(cmd.lc);
            if (cmd_data == NULL) {
                // Memory allocation failed, stop processing
                break;
            }
            memcpy(cmd_data, data, cmd.lc);
            cmd.data = cmd_data;
        } else {
            cmd.data = (uint8_t *) &dummy;
        }

        // Dispatch the APDU command
        // This tests:
        // - CLA validation
        // - INS routing to correct handler
        // - P1/P2 validation
        // - State machine consistency
        // - Handler robustness
        apdu_dispatcher(&cmd);

        // Reset APDU response state between commands so the next call to
        // apdu_response_begin() doesn't assert on leftover state from a
        // handler that exited early or via a non-standard path.
        apdu_response_state_force_reset();

        // Clean up allocated data
        if (cmd_data != NULL) {
            free(cmd_data);
        }

        // Advance to next command
        data += cmd.lc;
        size -= cmd.lc;
    }

    return 0;
}
