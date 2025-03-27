_Disclaimer: The author is NOT a cryptographer and this work has not been reviewed. This means that there is very likely a fatal flaw somewhere. Cashu is still experimental and not production-ready._

# Sig4Sats Script: Cashu-Nostr Signature Swaps

A simple script demonstrating how to atomically exchange Cashu payments for Nostr event signatures using Schnorr adaptor signatures.

## Overview

This project implements a cryptographic scheme using Schnorr signatures that enables Cashu payments conditioned on the signing of specific Nostr events. Using adaptor signatures, it allows a Payer to make a Cashu payment that can only be unlocked when the recipient provides a valid signature over a specific Nostr event ID.

The same scheme can be applied for on-chain transactions using Taproot without relying on Cashu mints.

## How It Works

1. **Setup**:

   - Both parties agree on the specific Nostr event to be signed

2. **Signer's Preparation**:

   - Signer **privately** creates a signature for the Nostr event
   - Signer shares **only** the public nonce (R_s) of his signature with the Payer

3. **Payer's Adaptor Signature**:

   - Payer computes the Nostr signature challenge using Signer's public nonce
   - Creates an adaptor point (T) as a commitment to the Nostr signature
   - Generates a Cashu proof secret using P2PK spending conditions
   - Creates an adaptor signature that binds the Cashu payment to the Nostr signature

4. **Signature Verification and Completion**:

   - Signer verifies the adaptor signature's validity
   - If valid, Signer completes the signature by adding their secret Nostr signature value
   - This creates the final Cashu scalar needed to claim the payment

5. **Payment Claiming**:

   - Signer submits the completed Cashu signature to the mint
   - The signature becomes public once the mint verifies and processes it

6. **Final Verification**:

   - Payer can extract the Signer's Nostr signature from the completed Cashu signature
   - The signed Nostr event can be verified and published to the network
   - Both parties get what they wanted: signature for satoshis.

## Installation and Usage

Currently [cashu-ts](https://github.com/cashubtc/cashu-ts) does not support the serialization of the Proof.witness field into V4 tokens, so until [this PR](https://github.com/cashubtc/cashu-ts/pull/280) is merged, you need to clone and compile this dependency locally:

```bash
cd ..
git clone -b development https://github.com/vstabile/cashu-ts.git
cd cashu-ts
npm install
npm run compile
cd ..
```

And then install this project

```bash
pnpm install
pnpm build
pnpm start
```

## Security Considerations

- Mint must implement Cashu NUT-07, NUT-10 and NUT-11
- Some implementations (e.g. cdk-mintd) announce support but fail to expose witness data properly. Do not trust Mint Info (NUT-06), verify!
- Unique nonces must be used for all signatures

## References

- [Cashu NUT-10](https://github.com/cashubtc/nuts/blob/main/10.md)
- [Cashu NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md)
- [Cashu NUT-07](https://github.com/cashubtc/nuts/blob/main/07.md)
- [Nostr Protocol](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [BIP340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
