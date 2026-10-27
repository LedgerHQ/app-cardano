# Babbage for HW wallets specification

[Cardano documentation for Alonzo](https://github.com/IntersectMBO/cardano-ledger)

### **Displaying txid**

HW wallets display txid (transaction body hash) for Plutus transactions. Users can use a trusted computer to assemble, check and serialize a transaction before submitting it to a HW wallet, and thus can verify that the transaction being signed by the HW wallet really is what they intend.

This gives the user an additional safety step which is easy to execute (one just needs to verify the equality of two 32-byte strings instead of all transaction details) and allows HW wallets to potentially hide unimportant details in order to improve UX.

We will extend showing txid to transactions that contain reference scripts and inline datums (which are arbitrarily long) in outputs.

### **Expert mode**

It turned out that most users of Plutus transactions don’t really care about maximum safety and prefer speed and simplicity when signing transactions. Non-expert users trust dapps and other tools and typically don’t want to be bothered with verifying collateral, datum hashes or other transaction elements whose meaning is not immediately obvious. This will be resolved by introducing two modes within HW wallets: *expert mode* showing all the relevant details and *non-expert* mode with simple and quick UI flows. Both major HW wallet vendors (Ledger and Trezor) agreed to having it implemented for Cardano and prefer this solution (vs. having detailed configuration options on what exactly is shown).

On Ledger HW wallets, several apps already offer an expert mode. The configuration option is permanently stored in the flash memory and is off by default. We will mimic this.

On Trezor, they don’t want any permanently stored configuration, so the user will choose at the beginning of the transaction. (This does not mean additional steps in the UI since Trezor’s screen is big enough to offer several options at once.)

The effect of expert vs. non-expert mode depends on transaction signing mode. The details can be found in the
[expert mode table](./expert_mode.xlsx).

As new elements are added to transactions, the expert mode will be extended accordingly.

Addition of the expert mode will also solve the problem with exporting keys and addresses: for the purpose of LedgerLive integration, Ledger requires apps to export public keys (and addresses) without confirmation. This encroaches on the privacy of users, so some might not like it at all. We will thus not allow unconfirmed key (and address) export in the expert mode.

# **New transaction elements**

### **Collateral return output and total amount of collateral**

    , ? 16 : transaction_output     ; collateral return; New
    , ? 17 : coin                   ; total collateral; New

Item 17 (*txColl*) is the total collateral amount in ADA. The user thus does not need to look at ADA amounts in collateral inputs (if their sum is not equal to txColl, transaction is deemed invalid by the blockchain).

HW wallets will only allow this optional item if signing mode is PLUTUS_TRANSACTION. If present, it will be displayed to users as "Total collateral".

Item 16 (*collRet*) is an output that is only created as an UTXO for transactions with failed phase-2 validation, i.e. when collateral was consumed. HW wallets will only allow this optional item if signing mode is PLUTUS_TRANSACTION.

For simplicity, we will not allow any datum or scripts in collRet, only ADA and tokens. (There is no known use case for including them there.) The allowed addresses for collRet are those Shelley addresses that have vkey hash in the payment part.

CollRet is supposed to contain all the excess ADA not consumed as collateral and all the tokens from collateral inputs. It must always be true that

(sum of tokens in collateral inputs) = (tokens in collRet)

Since collRet does not affect Plutus script evaluation, displaying tokens in collRet is redundant. But they are only mentioned implicitly through collateral inputs and there is a possibility of an attacker trying to steal tokens through a purposely failing transaction with small collateral value in ADA (in which case the user might be less attentive to collateral details), so it’s safer to display them anyway in all modes for third-party collateral outputs (i.e. when the HW wallet is giving away control over them).

**If txColl is given**, then

(sum of ADA in collateral inputs) = txColl + (ADA in collRet)

That means that if collRet is a change output, it is not possible to lose more than the explicitly given and displayed collateral, and since collateral inputs and outputs don’t affect Plutus script evaluation, we can safely hide collateral inputs. (The collateral inputs contain additional information about the specific distribution of tokens and ADA across UTXOs, but such information is hidden from users by all major SW wallets anyway, and those truly interested in it can use txid displayed at the end of the tx to verify it.)

For collRet, it is not safe to hide it in general since the address might not belong to the user. However, it is reasonable to hide change outputs (i.e. those with the payment part of the address being controlled by the HW wallet, which is proved by giving the key derivation path instead of a key hash).

Even though non-expert users don’t care about collateral, we will show them collRet anyway in case it is not a change output (its address, ADA amount and tokens): the sole fact that it is not a change output is suspicious and we will avoid a certain nasty attack by verifying just an address which is familiar to users: otherwise, it would be possible to use valuable user’s UTXOs as collateral inputs in a transaction that purposely fails phase-2 validation, stealing all valuables through a collateral output to an attacker’s address.

**If txColl is not given**, then

(sum of ADA in collateral inputs) >= (min collateral requirement) + (ADA in collRet)

We must thus show both collateral inputs and the ADA amount in collateral return output for expert users.

For non-expert users, it is better to display some explicit warning ("Warning: unknown collateral amount"). This warning makes sense even for expert users. (Not using txColl, which costs very little, complicates UI interactions and introduces the risk of overlooking implications arising from more complex interactions between transaction elements. If a potentially unlimited loss is at stake, we should not skimp on warnings.)

### **Reference inputs**

    , ? 18 : set<transaction_input> ; reference inputs; New

The data type is the same as for inputs and collateral inputs. These are not spent, but are important because they provide context for Plutus scripts. HW wallets will only allow this optional item if the signing mode is PLUTUS_TRANSACTION. If given, reference inputs will be shown to the user in expert mode (but will be hidden in non-expert mode).

### **Changes in outputs**

There is a major change in the serialization format of outputs: a map instead of an array (while the old output serialization format is still allowed). In the new format, one can choose to include datum or datum hash, and can also include reference scripts.

    post_alonzo_transaction_output =
      { 0 : address
      , 1 : value
      , ? 2 : datum      ; New; inline datum
      , ? 3 : script_ref ; New; script reference
      }
    datum = [ 0, $hash32 // 1, data ]
    data = #6.24(bytes .cbor plutus_data)
    script_ref = #6.24(bytes .cbor script)

Reference scripts should be allowed wherever datum/datum_hash is (i.e. in all transactions not involving pool registration), including in vkey outputs. (**Note: different from the current implementation which only supports datum in script outputs! That will be changed now.**)

Inline datums and scripts included in outputs are arbitrarily long. Since it is impractical to manually verify kilobytes of data on small HW wallet screens, we will only display a single screen showing the length of the data and a small initial chunk that fits the screen, as in the following example (the three dots won’t be used if the whole byte string is shown; "Script" will be used for scripts instead of "Datum").

    Datum 2704 bytes
    ab12c3deab12c3...

For subsequent chunks we don’t show anything and just silently serialize them into the tx. (Security is achieved by displaying and confirming txid at the end of the transaction.)

It is possible to extend the current code in such a way that both output types will be supported. There is no way around this; there are too many SW wallets and dapps. It might be possible in the future to drop support for the old format.

### **Required signers**

Apparently, required signers are being used even in transactions not involving Plutus validation. The security policies for required signers will be relaxed so that they can be used in any non-pool registration transaction (ordinary, multisig, Plutus).

# **Token registry information**

Amounts of native tokens are serialized as unsigned integers in the Cardano Ledger. However, they should be displayed to users with a number of decimal places that is given in [Cardano Token Registry](https://developers.cardano.org/docs/native-tokens/cardano-token-registry/). Unfortunately, this registry is not accessible to HW wallets, and not displaying the appropriate decimal places is very confusing to the users.

As a temporary solution, we will include in the HW wallets code a fixed table for the most commonly used native tokens (perhaps 50 or 100). This will be updated in the future or possibly replaced with another mechanism.
