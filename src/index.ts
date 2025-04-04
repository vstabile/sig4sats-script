import { schnorr, secp256k1 as secp } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import {
  generateSecretKey,
  UnsignedEvent,
  getEventHash,
  verifyEvent,
  getPublicKey,
} from "nostr-tools";
import { negateScalar, sleep } from "./utils";
import {
  CashuMint,
  CashuWallet,
  CheckStateEnum,
  getDecodedToken,
  getEncodedTokenV4,
  MintQuoteState,
  Proof,
} from "@cashu/cashu-ts";
import { hashToCurve } from "@cashu/crypto/modules/common";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

async function main() {
  // ----------------------------------------
  // Users Setup
  // Payer: Buys the Signer's signature over a Nostr event
  // Signer: Reveals the signature by claiming the Payer's Cashu payment
  // ----------------------------------------

  // Payer key pair
  let k_p = generateSecretKey();
  let P_p = getPublicKey(k_p);
  console.log("Payer Public Key:", P_p);

  // Signer key pair
  let k_s = generateSecretKey();
  let P_s = getPublicKey(k_s);
  console.log("Signer Public Key:", P_s, "\n");

  // Payer mints Cashu proofs using P2PK spending conditions
  // NUT-10: https://github.com/cashubtc/nuts/blob/main/10.md
  // NUT-11: https://github.com/cashubtc/nuts/blob/main/11.md
  const mintUrl = "https://testnut.cashu.space";
  const paymentAmount = 130;
  const mint = new CashuMint(mintUrl);
  const mintInfo = await mint.getInfo();
  const isSupported =
    mintInfo.nuts["7"]?.supported &&
    mintInfo.nuts["10"]?.supported &&
    mintInfo.nuts["11"]?.supported;
  if (!isSupported) {
    console.log("Mint does not support NUT-07, NUT-10 and NUT-11", "\n");
    throw new Error("Mint does not support NUT-07, NUT-10 and NUT-11");
  }

  const wallet = new CashuWallet(mint);
  await wallet.loadMint();
  const mintQuote = await wallet.createMintQuote(paymentAmount);

  let proofs: Proof[] = [];
  while (!proofs.length) {
    const status = await wallet.checkMintQuote(mintQuote.quote);
    if (status.state === MintQuoteState.PAID) {
      proofs = await wallet.mintProofs(paymentAmount, mintQuote.quote, {
        pubkey: "02" + P_p, // Locks proofs to the Payer's pubkey
      });
    }
    await sleep(1000);
  }

  // ----------------------------------------
  // Step 1: Payer and Signer agree on the specific Nostr event ID
  // ----------------------------------------

  const nostrEvent: UnsignedEvent = {
    kind: 1,
    pubkey: P_s, // The event will be signed by the Signer
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: "Hello world",
  };

  const nostrEventId = getEventHash(nostrEvent);

  console.log("Nostr Event ID:", nostrEventId);

  // ----------------------------------------
  // Step 2: Signer privately signs the event and shares its public nonce
  // ----------------------------------------

  const secretSignature = schnorr.sign(nostrEventId, k_s);

  // Public nonce of the Nostr event signature
  const R_s_x = secretSignature.subarray(0, 32);

  // Signer shares the public nonce with the Payer
  console.log("Signer's Public Nonce (shared):", bytesToHex(R_s_x), "\n");

  // ----------------------------------------
  // Step 3: Payer creates an adaptor signature for claiming his Cashu payment
  // ----------------------------------------

  // Payer computes the Nostr signature challenge using Signer's public nonce:
  // c_nostr = H(R_s || P_s || m)
  const c_nostr = schnorr.utils.taggedHash(
    "BIP0340/challenge",
    new Uint8Array([...R_s_x, ...hexToBytes(P_s), ...hexToBytes(nostrEventId)])
  );

  // Then computes the Signer's public nonce point on the curve
  const R_s = schnorr.utils.lift_x(BigInt("0x" + bytesToHex(R_s_x)));

  // And computes the adaptor point T as a commitment to the Nostr signature:
  // T = R_s + c_nostr * P_s
  let T = R_s.add(
    schnorr.utils
      .lift_x(BigInt("0x" + P_s))
      .multiply(BigInt("0x" + bytesToHex(c_nostr)))
  );

  console.log("Adaptor Point (T):", T.toHex(), "\n");

  // Payer generates an adaptor signature for each proof using a unique nonce
  let adaptors: Record<
    string,
    { s_a: bigint; R_p_x: Uint8Array; R_a_x: Uint8Array }
  > = {};
  for (const [i, proof] of proofs.entries()) {
    // First he generates a nonce (r_p) and the adaptor public nonce (R_p + T)
    // ensuring that both R_p and R_a = (R_p + T) have even y-coordinates (BIP340)
    let r_p, R_p, R_a;
    do {
      r_p = schnorr.utils.randomPrivateKey();
      R_p = secp.ProjectivePoint.fromPrivateKey(r_p);

      // Negate the nonce if its point has an odd y-coordinate
      if ((R_p.y & 1n) === 1n) {
        r_p = negateScalar(r_p);
        R_p = R_p.negate();
      }

      R_a = R_p.add(T);
      // Try again if the adaptor nonce has an odd y-coordinate
    } while ((R_a.y & 1n) === 1n);

    // Adaptor nonce X-coordinate
    const R_a_x = hexToBytes(R_a.x.toString(16).padStart(64, "0"));
    // Payer's nonce X-coordinate
    const R_p_x = hexToBytes(R_p.x.toString(16).padStart(64, "0"));

    // Then calculates the Cashu P2PK challenge: H(R + T || P_p || m)
    const c_cashu = schnorr.utils.taggedHash(
      "BIP0340/challenge",
      new Uint8Array([...R_a_x, ...hexToBytes(P_p), ...sha256(proof.secret)])
    );

    // Scalars conversion to BigInt for arithmetic operations
    const r = BigInt(`0x${bytesToHex(r_p)}`) % secp.CURVE.n;
    let c = BigInt(`0x${bytesToHex(c_cashu)}`) % secp.CURVE.n;
    const k = BigInt(`0x${bytesToHex(k_p)}`) % secp.CURVE.n;

    // The challenge must be negated if Payer's private key is associated with
    // a point on the curve with an odd y-coordinate (BIP340)
    const P_p_point = secp.ProjectivePoint.fromPrivateKey(k_p);
    if ((P_p_point.y & 1n) === 1n) {
      c = secp.CURVE.n - c;
    }

    // The payer calculates the adaptor scalar: s_a = r_p + c_cashu * k_p
    const s_a = (r + ((c * k) % secp.CURVE.n)) % secp.CURVE.n;

    // The adaptor contains the scalar s_a, the payer's nonce R_p and the point T
    const Y = hashToCurve(new TextEncoder().encode(proof.secret)).toHex(true);
    adaptors = { ...adaptors, [Y]: { s_a, R_p_x, R_a_x } };

    // Payer shares the adaptors with the Signer
    console.log("Proof", Y);
    console.log("Adaptor Scalar (s_a):", s_a.toString(16));
    console.log("Signer Nonce (R_p):", bytesToHex(R_p_x));
    console.log("Adaptor Nonce (R_a):", bytesToHex(R_a_x), "\n");
  }

  // Payer shares the locked Cashu token with the Signer
  const lockedToken = getEncodedTokenV4({ mint: mintUrl, proofs });

  console.log("Locked Cashu token:", lockedToken, "\n");

  // ----------------------------------------
  // Step 4: Signer verifies the mint, token amount and the adaptor signature.
  // If everything is correct, the Signer completes the signature.
  // ----------------------------------------

  // Signer decodes the locked Cashu token
  const decodedToken = getDecodedToken(lockedToken);

  // Signer verifies the token mint
  if (decodedToken.mint !== mintUrl) {
    console.error("❌ Token mint is invalid!", "\n");
  }

  // Signer verifies the token amount
  const uniqueSecrets = new Set(decodedToken.proofs.map((p) => p.secret));
  const areSecretsUnique = uniqueSecrets.size === decodedToken.proofs.length;
  const totalAmount = decodedToken.proofs.reduce(
    (sum, { amount }) => sum + amount,
    0
  );

  if (!areSecretsUnique && totalAmount !== paymentAmount) {
    console.error("❌ Token amount is invalid!", "\n");
  }

  // Signer calculates the cashu challenge for each proof
  let cashuChallenges: Record<string, bigint> = {};
  for (const [i, proof] of proofs.entries()) {
    const Y = hashToCurve(new TextEncoder().encode(proof.secret)).toHex(true);

    const c_cashu = schnorr.utils.taggedHash(
      "BIP0340/challenge",
      new Uint8Array([
        ...adaptors[Y].R_a_x,
        ...hexToBytes(P_p),
        ...sha256(proof.secret),
      ])
    );

    cashuChallenges = {
      ...cashuChallenges,
      [Y]: BigInt(`0x${bytesToHex(c_cashu)}`),
    };
  }

  // Signer verifies each adaptor signature:
  // s_a * G ?= R_p + H(R_p + T || P_p || m) * P_p
  let areAdaptorsValid = true;
  for (const [Y, { s_a, R_p_x }] of Object.entries(adaptors)) {
    const R_p = schnorr.utils.lift_x(BigInt("0x" + bytesToHex(R_p_x)));

    const left = secp.ProjectivePoint.BASE.multiply(s_a);
    const rightEven = R_p.add(
      schnorr.utils.lift_x(BigInt("0x" + P_p)).multiply(cashuChallenges[Y])
    );
    // He needs to check the case where the Payer's private key is associated with
    // a point on the curve with an odd y-coordinate (BIP340) by negating the challenge
    const rightOdd = R_p.add(
      schnorr.utils
        .lift_x(BigInt("0x" + P_p))
        .multiply(secp.CURVE.n - cashuChallenges[Y])
    );

    // The adaptor signature is valid if one of the verifications is valid
    if (!left.equals(rightEven) && !left.equals(rightOdd)) {
      areAdaptorsValid = false;
    }
  }

  if (areAdaptorsValid) {
    console.log("✅ Adaptor signatures are all valid!", "\n");
  } else {
    console.error("❌ Adaptor signatures are invalid!", "\n");
  }

  // Then the Signer completes the signatures by adding the hidden value (t)
  // which is his Nostr signature over the Nostr event ID
  const t = BigInt(`0x${bytesToHex(secretSignature.subarray(32))}`);

  let cashuSignatures: string[] = [];
  for (const [Y, { s_a, R_a_x }] of Object.entries(adaptors)) {
    // The Signer calculates the Cashu scalar: s_c = s_a + t
    const s_c = (s_a + t) % secp.CURVE.n;

    // The Cashu signature is the adaptor nonce (R_a) and the Cashu scalar (s_c)
    const cashuSignature = bytesToHex(
      new Uint8Array([
        ...R_a_x,
        ...hexToBytes(s_c.toString(16).padStart(64, "0")),
      ])
    );

    cashuSignatures.push(cashuSignature);

    console.log("Proof", Y);
    console.log("Cashu Scalar (s_c):", s_c.toString(16).padStart(64, "0"));
    console.log("Cashu Signature:", cashuSignature, "\n");
  }

  // -------------------------------
  // Step 5: The Signer claims the Payer's Cashu payment
  // -------------------------------

  // Signer uses the Cashu scalar (s_c) with the adaptor nonce (R_a) to claim
  // the Payer's Cashu payment. This complete signature will be made public by
  // the Cashu Mint as long as it implements Token State Check (NIP-7):
  // https://github.com/cashubtc/nuts/blob/main/07.md

  // Signer adds the signatures to the proofs
  const signedProofs = proofs.map((proof, index) => ({
    ...proof,
    witness: { signatures: [cashuSignatures[index]] },
  }));

  const unlockedToken = getEncodedTokenV4({
    mint: mintUrl,
    proofs: signedProofs,
  });

  const claimedProofs = await wallet.receive(unlockedToken);

  if (claimedProofs.length === proofs.length) {
    console.log("✅ Cashu signatures are all valid!", "\n");
  } else {
    console.error("❌ Cashu signatures are invalid!", "\n");
  }

  // -------------------------------
  // Step 6: The Payer extracts the Signer's Nostr signature
  // -------------------------------

  // The Payer retrieves the complete signature from the Cashu Mint (NIP-7)
  let proofStates = await wallet.checkProofsStates(proofs);

  const spentProofs = proofStates.filter(
    (p) => p.state === CheckStateEnum.SPENT
  );

  if (spentProofs.length === 0) {
    console.error("❌ Cashu signatures were not spent yet!", "\n");
  }

  const Y = spentProofs[0].Y;
  const proofSignature = JSON.parse(spentProofs[0].witness!).signatures[0];

  // Extracts the Signer's secret (Nostr event signature)
  const s_c = BigInt(`0x${proofSignature.substring(64)}`);

  const s_a = adaptors[Y].s_a;

  let extractedSecret = (s_c - s_a + secp.CURVE.n) % secp.CURVE.n;

  console.log(
    "Extracted Secret (t = s_c - s_a):",
    extractedSecret.toString(16),
    "\n"
  );

  // And can now publish the signed Nostr event to the network
  const nostrSignature = bytesToHex(
    new Uint8Array([
      ...R_s_x, // Signer's public nonce shared in Step 2
      ...hexToBytes(extractedSecret.toString(16).padStart(64, "0")),
    ])
  );

  const signedEvent = {
    id: nostrEventId,
    ...nostrEvent,
    sig: nostrSignature,
  };

  // Relays verify the Nostr event signature
  const isNostrEventValid = verifyEvent(signedEvent);

  if (isNostrEventValid) {
    console.log("✅ Nostr event signature is valid!");
  } else {
    console.error("❌ Nostr event signature is invalid!");
  }
}

main().catch(console.error);
