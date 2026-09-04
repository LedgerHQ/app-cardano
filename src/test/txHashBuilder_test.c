#ifdef DEVEL

#include "txHashBuilder.h"
#include "cardano.h"
#include "hexUtils.h"
#include "testUtils.h"

// Mainnet enterprise (script) address: header 0x71 + 28-byte script hash. This
// is the RealFi proxy multisig address. The proxy NFT sits at this address with
// an empty asset name, and the proxy update output carries a large inline datum.
// That exact output shape rebooted the device once the serialized inline datum
// reached 1024 bytes.
static const char *proxyScriptAddressHex =
    "714cd932b75282c52c1e6710cd938e7f07ce6757dbba7d389a55488879";
static const char *proxyNftPolicyIdHex = "b1a939dd2bed1ba23ea3d10bb00819891154a96c456c43692ee9a54c";

// Builds the body hash for a single Babbage output that holds the proxy NFT
// (empty asset name) plus an inline datum of inlineDatumSize bytes, every byte
// 0xAB. The datum is streamed in chunks, exactly as signTxOutput drives it.
static void buildProxyUpdateTxHash(size_t inlineDatumSize, uint8_t *outHash) {
    tx_hash_builder_t builder;
    // The production builder lives in the instruction state, which is zeroed
    // before signing. Mirror that here so output-state fields start clean.
    explicit_bzero(&builder, SIZEOF(builder));

    txHashBuilder_init(&builder,
                       false,  // tagCborSets
                       1,      // numInputs
                       1,      // numOutputs
                       false,  // includeTtl
                       0,      // numCertificates
                       0,      // numWithdrawals
                       false,  // includeAuxData
                       false,  // includeValidityIntervalStart
                       false,  // includeMint
                       false,  // includeScriptDataHash
                       0,      // numCollateralInputs
                       0,      // numRequiredSigners
                       false,  // includeNetworkId
                       false,  // includeCollateralOutput
                       false,  // includeTotalCollateral
                       0,      // numReferenceInputs
                       0,      // numVotingProcedures
                       false,  // includeTreasury
                       false   // includeDonation
    );

    txHashBuilder_enterInputs(&builder);
    {
        tx_input_t input;
        explicit_bzero(&input, SIZEOF(input));
        // all-zero tx hash, output index 0
        input.index = 0;
        txHashBuilder_addInput(&builder, &input);
    }

    txHashBuilder_enterOutputs(&builder);
    {
        uint8_t addressBuffer[29] = {0};
        size_t addressSize =
            decode_hex(proxyScriptAddressHex, addressBuffer, SIZEOF(addressBuffer));

        tx_output_description_t output;
        explicit_bzero(&output, SIZEOF(output));
        output.format = MAP_BABBAGE;
        output.destination.type = DESTINATION_THIRD_PARTY;
        output.destination.address.buffer = addressBuffer;
        output.destination.address.size = addressSize;
        output.amount = 10000000;
        output.numAssetGroups = 1;
        output.includeDatum = true;
        output.includeRefScript = false;

        txHashBuilder_addOutput_topLevelData(&builder, &output);

        uint8_t policyId[MINTING_POLICY_ID_SIZE] = {0};
        decode_hex(proxyNftPolicyIdHex, policyId, SIZEOF(policyId));
        txHashBuilder_addOutput_tokenGroup(&builder, policyId, SIZEOF(policyId), 1);

        // empty asset name, amount 1 (single NFT)
        uint8_t emptyAssetName[1] = {0};
        txHashBuilder_addOutput_token(&builder, emptyAssetName, 0, 1);

        // The call below previously rebooted the device for inlineDatumSize >= 1024
        // via a spurious ASSERT on the total size. The datum is streamed, so the
        // total is never held in a single buffer.
        txHashBuilder_addOutput_datum(&builder, DATUM_INLINE, NULL, inlineDatumSize);

        uint8_t chunk[240] = {0};
        for (size_t i = 0; i < SIZEOF(chunk); i++) {
            chunk[i] = 0xAB;
        }
        size_t remaining = inlineDatumSize;
        while (remaining > 0) {
            size_t chunkSize = remaining < SIZEOF(chunk) ? remaining : SIZEOF(chunk);
            txHashBuilder_addOutput_datum_inline_chunk(&builder, chunk, chunkSize);
            remaining -= chunkSize;
        }
    }

    txHashBuilder_addFee(&builder, 200000);

    txHashBuilder_finalize(&builder, outHash, TX_HASH_LENGTH);
}

// 1023-byte inline datum: just under the limit. Signs on both the old and the
// fixed app; here it guards against regressing the streamed-hash result.
void test_inlineDatum_justUnderLimit() {
    PRINTF("inline datum 1023 bytes (just under 1 KiB)\n");

    uint8_t hash[TX_HASH_LENGTH] = {0};
    buildProxyUpdateTxHash(1023, hash);

    uint8_t expected[TX_HASH_LENGTH] = {0};
    decode_hex("bb35a0c42c26cdea5de768381e5385bbffcf16b5adc150e74714912f4f32d04b",
               expected,
               SIZEOF(expected));

    PRINTF("tx hash hex\n");
    PRINTF("%.*h\n", TX_HASH_LENGTH, hash);

    EXPECT_EQ_BYTES(hash, expected, TX_HASH_LENGTH);
}

// 1024-byte inline datum: just over the limit. This is the regression. The old
// app failed ASSERT(bufferSize < BUFFER_SIZE_PARANOIA) in
// txHashBuilder_addOutput_datum and rebooted; the fixed app hashes it cleanly.
void test_inlineDatum_atLimit() {
    PRINTF("inline datum 1024 bytes (regression, 1 KiB)\n");

    uint8_t hash[TX_HASH_LENGTH] = {0};
    buildProxyUpdateTxHash(1024, hash);

    uint8_t expected[TX_HASH_LENGTH] = {0};
    decode_hex("013777c7232a743e5698f3ff23e8280259fdaa86fc87b6184a501baad0f96ee4",
               expected,
               SIZEOF(expected));

    PRINTF("tx hash hex\n");
    PRINTF("%.*h\n", TX_HASH_LENGTH, hash);

    EXPECT_EQ_BYTES(hash, expected, TX_HASH_LENGTH);
}

void run_txHashBuilder_test() {
    PRINTF("txHashBuilder test\n");

    test_inlineDatum_justUnderLimit();
    test_inlineDatum_atLimit();
}

#endif  // DEVEL
