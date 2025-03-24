# Sig4Sats Script: Cashu-Nostr Signature Swaps

A simple script demonstrating how to atomically exchange Cashu payments for Nostr event signatures using Schnorr adaptor signatures.

## Overview

This project implements a cryptographic scheme using Schnorr signatures that enables Cashu payments conditioned on the signing of specific Nostr events. Using adaptor signatures, it allows a Payer to make a Cashu payment that can only be unlocked when the recipient provides a valid signature over a specific Nostr event ID.

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

```bash
pnpm install
pnpm build
pnpm start
```

## Security Considerations

- Unique nonces must be used for all signatures
- Mint must implement Cashu NUT-07, NUT-10 and NUT-11

## References

- [Cashu NUT-10](https://github.com/cashubtc/nuts/blob/main/10.md)
- [Cashu NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md)
- [Cashu NUT-7](https://github.com/cashubtc/nuts/blob/main/07.md)
- [Nostr Protocol](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [BIP340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
