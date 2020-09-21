#include "messageSigning.h"
#include "cardano.h"
#include "keyDerivation.h"

void signRawMessage(privateKey_t* privateKey,
                    const uint8_t* messageBuffer, size_t messageSize,
                    uint8_t* outBuffer, size_t outSize)
{
	uint8_t signature[64];
	ASSERT(messageSize < BUFFER_SIZE_PARANOIA);
	ASSERT(outSize == SIZEOF(signature));

	// Note(ppershing): this could be done without
	// temporary copy
	STATIC_ASSERT(sizeof(int) == sizeof(size_t), "bad sizing");
	io_seproxyhal_io_heartbeat();
	size_t signatureSize =
	        (size_t) cx_eddsa_sign(
	                (const struct cx_ecfp_256_private_key_s*) privateKey,
	                0 /* mode */,
	                CX_SHA512,
	                messageBuffer, messageSize,
	                NULL /* ctx */, 0 /* ctx len */,
	                signature, SIZEOF(signature),
	                0 /* info */
	        );
	io_seproxyhal_io_heartbeat();

	ASSERT(signatureSize == 64);
	os_memmove(outBuffer, signature, signatureSize);
}

void getTxWitness(bip44_path_t* pathSpec,
                  const uint8_t* txHashBuffer, size_t txHashSize,
                  uint8_t* outBuffer, size_t outSize)
{
	chain_code_t chainCode;
	privateKey_t privateKey;

	// TODO is this the proper key for both Byron and Shelley?
	TRACE("derive private key");

	BEGIN_TRY {
		TRY {
			derivePrivateKey(pathSpec, &chainCode, &privateKey);

			ASSERT(txHashSize == TX_HASH_LENGTH);

			signRawMessage(
			        &privateKey,
			        txHashBuffer, txHashSize,
			        outBuffer, outSize
			);
		}
		FINALLY {
			explicit_bzero(&privateKey, SIZEOF(privateKey));
			explicit_bzero(&chainCode, SIZEOF(chainCode));
		}
	} END_TRY;
}