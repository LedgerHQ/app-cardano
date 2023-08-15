#ifndef H_CARDANO_APP_KEY_DERIVATION
#define H_CARDANO_APP_KEY_DERIVATION

#include "common.h"
#include "handlers.h"
#include "bip44.h"

#define PUBLIC_KEY_SIZE      (32)
#define CHAIN_CODE_SIZE      (32)
#define EXTENDED_PUBKEY_SIZE (CHAIN_CODE_SIZE + PUBLIC_KEY_SIZE)

typedef cx_ecfp_256_extended_private_key_t privateKey_t;

typedef struct {
	uint8_t code[CHAIN_CODE_SIZE];
} chain_code_t;

typedef struct {
	uint8_t pubKey[PUBLIC_KEY_SIZE];
	uint8_t chainCode[CHAIN_CODE_SIZE];
} extendedPublicKey_t;


void deriveExtendedPublicKey(
        const bip44_path_t* pathSpec,
        extendedPublicKey_t* out
);


#ifdef DEVEL
void run_key_derivation_test();
#endif // DEVEL

#endif // H_CARDANO_APP_KEY_DERIVATION
