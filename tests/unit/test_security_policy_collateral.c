/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "addressUtilsShelley.h"
#include "addressUtils/bip44.h"
#include "transaction/tx_output_types.h"
#include "transaction/tx_parse_outputs.h"
#include "cardano_constants.h"
#include "globals.h"

extern bool unit_test_expert_mode_enabled;

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

static bip44_path_t make_payment_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 0;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_staking_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 2;
    path.path[4] = index;
    return path;
}

static void init_standard_device_owned_address_params(address_params_t *params) {
    assert_non_null(params);
    memset(params, 0, sizeof(*params));

    params->type = BASE_PAYMENT_KEY_STAKE_KEY;
    params->networkId = MAINNET_NETWORK_ID;
    params->paymentPartType = PAYMENT_PART_KEY_PATH;
    params->paymentKeyPath = make_payment_path(0, 0);
    params->stakingPartType = STAKING_PART_KEY_PATH;
    params->stakingKeyPath = make_staking_path(0, 0);
}

static void init_third_party_enterprise_address(uint8_t *address, size_t address_size) {
    assert_non_null(address);
    assert_int_equal(address_size, 1 + ADDRESS_KEY_HASH_LENGTH);

    memset(address, 0, address_size);
    address[0] = constructShelleyAddressHeader(ENTERPRISE_KEY, MAINNET_NETWORK_ID);
    for (size_t i = 1; i < address_size; i++) {
        address[i] = (uint8_t) i;
    }
}

static tx_output_description_t make_collateral_output_description_device_owned(
    uint16_t num_asset_groups) {
    static address_params_t params;
    init_standard_device_owned_address_params(&params);

    tx_output_description_t output = {
        .destination =
            {
                .type = DESTINATION_DEVICE_OWNED,
                .params = params,
            },
        .amount = 1,
        .numAssetGroups = num_asset_groups,
        .includeDatum = false,
        .includeRefScript = false,
        .format = ARRAY_LEGACY,
    };
    return output;
}

static tx_output_description_t make_collateral_output_description_third_party(
    uint16_t num_asset_groups) {
    static uint8_t address[1 + ADDRESS_KEY_HASH_LENGTH];
    init_third_party_enterprise_address(address, SIZEOF(address));

    tx_output_description_t output = {
        .destination = tx_output_destination_make_third_party(address, SIZEOF(address)),
        .amount = 1,
        .numAssetGroups = num_asset_groups,
        .includeDatum = false,
        .includeRefScript = false,
        .format = ARRAY_LEGACY,
    };
    return output;
}

static void test_collateral_output_top_level_policy_device_owned(void **state) {
    (void) state;
    reset_context();

    tx_output_description_t output = make_collateral_output_description_device_owned(0);
    warning_bits_t w = 0;

    security_policy_t policy_without_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               false,
                                               &w);
    assert_int_equal(policy_without_total, POLICY_SHOW);

    security_policy_t policy_with_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               true,
                                               &w);
    assert_int_equal(policy_with_total, POLICY_HIDE);
}

static void test_collateral_output_top_level_policy_third_party(void **state) {
    (void) state;
    reset_context();

    tx_output_description_t output = make_collateral_output_description_third_party(0);
    warning_bits_t w = 0;

    security_policy_t policy_without_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               false,
                                               &w);
    assert_int_equal(policy_without_total, POLICY_SHOW);

    security_policy_t policy_with_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               true,
                                               &w);
    assert_int_equal(policy_with_total, POLICY_SHOW);
}

static void test_collateral_output_subpolicy_matrix(void **state) {
    (void) state;
    reset_context();

    typedef struct {
        sign_tx_signingmode_t signing_mode;
        bool expert_mode;
        bool total_collateral_present;
        bool device_owned;
        security_policy_t expected_address_policy;
        security_policy_t expected_ada_policy;
        security_policy_t expected_tokens_policy;
    } collateral_output_policy_row_t;

    // short names for the middle columns of the policy table below
    const bool expert_off = false;
    const bool expert_on = true;
    const bool no_total = false;
    const bool total = true;
    const bool third_party = false;
    const bool device_owned = true;
    const security_policy_t shown = POLICY_SHOW;
    const security_policy_t hidden = POLICY_HIDE;

    // clang-format off
    const collateral_output_policy_row_t rows[] = {
        // signing mode,                  expert      total      output        address  ADA      tokens

        // third-party output: address, ADA amount and tokens are always shown
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_off, no_total,  third_party,  shown,   shown,   POLICY_SHOW},
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_off, total,     third_party,  shown,   shown,   POLICY_SHOW},
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_on,  no_total,  third_party,  shown,   shown,   POLICY_SHOW},
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_on,  total,     third_party,  shown,   shown,   POLICY_SHOW},
        {SIGN_TX_SIGNINGMODE_UNRESTRICTED, expert_on,  no_total,  third_party,  shown,   shown,   POLICY_SHOW},
        {SIGN_TX_SIGNINGMODE_UNRESTRICTED, expert_on,  total,     third_party,  shown,   shown,   POLICY_SHOW},

        // device-owned output with total collateral: the loss is bounded by the total
        // collateral, so a standard change output is hidden (unrestricted always shows the address)
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_off, total,     device_owned, hidden,  hidden,  POLICY_HIDE},
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_on,  total,     device_owned, hidden,  hidden,  POLICY_HIDE},
        {SIGN_TX_SIGNINGMODE_UNRESTRICTED, expert_on,  total,     device_owned, shown,   hidden,  POLICY_HIDE},

        // device-owned output without total collateral: address shown, ADA amount only in expert mode
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_off, no_total,  device_owned, shown,   hidden,  POLICY_HIDE},
        {SIGN_TX_SIGNINGMODE_PLUTUS,       expert_on,  no_total,  device_owned, shown,   shown,   POLICY_HIDE},
        {SIGN_TX_SIGNINGMODE_UNRESTRICTED, expert_on,  no_total,  device_owned, shown,   shown,   POLICY_HIDE},
    };
    // clang-format on

    for (size_t row_index = 0; row_index < ARRAY_LEN(rows); row_index++) {
        const collateral_output_policy_row_t *row = &rows[row_index];
        unit_test_expert_mode_enabled = row->expert_mode;

        // one asset group, so that tokens are actually present in the output
        tx_output_description_t output = row->device_owned
                                             ? make_collateral_output_description_device_owned(1)
                                             : make_collateral_output_description_third_party(1);
        warning_bits_t w = 0;

        security_policy_t address_policy =
            policyForSignTxCollateralOutputAddress(&output,
                                                   row->signing_mode,
                                                   MAINNET_NETWORK_ID,
                                                   MAINNET_PROTOCOL_MAGIC,
                                                   row->total_collateral_present,
                                                   &w);
        assert_int_equal(address_policy, row->expected_address_policy);

        security_policy_t ada_policy =
            policyForSignTxCollateralOutputAdaAmount(address_policy,
                                                     row->signing_mode,
                                                     &output,
                                                     row->total_collateral_present,
                                                     &w);
        assert_int_equal(ada_policy, row->expected_ada_policy);

        security_policy_t tokens_policy =
            policyForSignTxCollateralOutputTokens(address_policy, row->signing_mode, &output, &w);
        assert_int_equal(tokens_policy, row->expected_tokens_policy);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_collateral_output_top_level_policy_device_owned),
        cmocka_unit_test(test_collateral_output_top_level_policy_third_party),
        cmocka_unit_test(test_collateral_output_subpolicy_matrix),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
