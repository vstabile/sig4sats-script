import { schnorr, secp256k1 as secp } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import {
  generateSecretKey,
  UnsignedEvent,
  getEventHash,
  verifyEvent,
  getPublicKey,
} from "nostr-tools";
import { negateScalar } from "./utils";

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
console.log(
  "Bob's Public Nonce (shared):",
  Buffer.from(R_s_x).toString("hex"),
  "\n"
);

// ----------------------------------------
// Step 3: Payer creates an adaptor signature for claiming his Cashu payment
// ----------------------------------------

// Payer computes the Nostr signature challenge using Bob's public nonce:
// c_nostr = H(R_s || P_s || m)
const c_nostr = schnorr.utils.taggedHash(
  "BIP0340/challenge",
  Buffer.concat([
    R_s_x,
    Buffer.from(P_s, "hex"),
    Buffer.from(nostrEventId, "hex"),
  ])
);

// Then computes the Signer's public nonce point on the curve
const R_s = schnorr.utils.lift_x(
  BigInt("0x" + Buffer.from(R_s_x).toString("hex"))
);

// And computes the adaptor point T as a commitment to the Nostr signature:
// T = R_s + c_nostr * P_s
let T = R_s.add(
  schnorr.utils
    .lift_x(BigInt("0x" + P_s))
    .multiply(BigInt("0x" + Buffer.from(c_nostr).toString("hex")))
);

console.log("Adaptor Point (T):", T.toHex(), "\n");

// Payer creates the Cashu Proof.secret for claiming his payment
// using P2PK spending conditions according to NUT-10 and NUT-11:
// https://github.com/cashubtc/nuts/blob/main/10.md
// https://github.com/cashubtc/nuts/blob/main/11.md
const cashuSecret = JSON.stringify([
  "P2PK",
  {
    nonce: Buffer.from(schnorr.utils.randomPrivateKey()).toString("hex"),
    data: P_p,
  },
]);

const cashuSecretHash = Buffer.from(sha256(cashuSecret)).toString("hex");

console.log("Payer's Cashu Proof.secret hash:", cashuSecretHash, "\n");

// Payer generates a nonce (r_p) and the adaptor public nonce (R_p + T)
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
const R_a_x = Buffer.from(R_a.x.toString(16).padStart(64, "0"), "hex");

// Then calculates the Cashu P2PK challenge: H(R + T || P_p || m)
const c_cashu = schnorr.utils.taggedHash(
  "BIP0340/challenge",
  Buffer.concat([
    R_a_x,
    Buffer.from(P_p, "hex"),
    Buffer.from(cashuSecretHash, "hex"),
  ])
);

// Scalars conversion to BigInt for arithmetic operations
const r = BigInt(`0x${Buffer.from(r_p).toString("hex")}`) % secp.CURVE.n;
let c = BigInt(`0x${Buffer.from(c_cashu).toString("hex")}`) % secp.CURVE.n;
const k = BigInt(`0x${Buffer.from(k_p).toString("hex")}`) % secp.CURVE.n;

// The challenge must be negated if Alice's private key is associated with
// a point on the curve with an odd y-coordinate (BIP340)
const P_p_point = secp.ProjectivePoint.fromPrivateKey(k_p);
if ((P_p_point.y & 1n) === 1n) {
  c = secp.CURVE.n - c;
}

// The payer calculates the adaptor scalar: s_a = r_p + c_cashu * k_p
const s_a = (r + ((c * k) % secp.CURVE.n)) % secp.CURVE.n;

// The adaptor signature is the scalar s_a and the public nonce R_a
console.log("Adaptor Signature Scalar (s_a):", s_a.toString(16));
console.log(
  "Adaptor Public Nonce (R_a):",
  Buffer.from(R_a_x).toString("hex"),
  "\n"
);

// ----------------------------------------
// Step 4: Signer verifies the adaptor signature and completes it
// ----------------------------------------

// Signer verifies the adaptor signature:
// s_a * G ?= R_p + H(R + T || P_p || m) * P_p
const left = secp.ProjectivePoint.BASE.multiply(s_a);
const rightEven = R_p.add(schnorr.utils.lift_x(BigInt("0x" + P_p)).multiply(c));
// He needs to check the case where the Payer's private key is associated with
// a point on the curve with an odd y-coordinate (BIP340) by negating the challenge
const rightOdd = R_p.add(
  schnorr.utils.lift_x(BigInt("0x" + P_p)).multiply(secp.CURVE.n - c)
);

// The adaptor signature is valid if one of the verifications is valid
if (left.equals(rightEven) || left.equals(rightOdd)) {
  console.log("✅ Adaptor signature is valid!", "\n");
} else {
  console.error("❌ Adaptor signature is invalid!", "\n");
}

// Then the Signer completes the signature by adding the hidden value (t)
// which is his Nostr signature over the Nostr event ID
const t = BigInt(
  `0x${Buffer.from(secretSignature.subarray(32)).toString("hex")}`
);

// The Signer calculates the Cashu scalar: s_c = s_a + t
const s_c = (s_a + t) % secp.CURVE.n;
console.log("Cashu Scalar (s_c):", s_c.toString(16).padStart(64, "0"));

// -------------------------------
// Step 5: The Signer claims the Payer's Cashu payment
// -------------------------------

// Signer uses the Cashu scalar (s_c) with the adaptor nonce (R_a) to claim
// the Payer's Cashu payment. This complete signature will be made public by
// the Cashu Mint as long as it implements Token State Check (NIP-7):
// https://github.com/cashubtc/nuts/blob/main/07.md
const cashuSignature = Buffer.concat([
  R_a_x,
  Buffer.from(s_c.toString(16).padStart(64, "0"), "hex"),
]).toString("hex");

console.log("Cashu Signature:", cashuSignature, "\n");

// The Mint verifies the Cashu signature
const isCashuSignatureValid = schnorr.verify(
  cashuSignature,
  cashuSecretHash,
  P_p
);

if (isCashuSignatureValid) {
  console.log("✅ Cashu secret signature is valid!", "\n");
} else {
  console.error("❌ Cashu secret signature is invalid!", "\n");
}

// -------------------------------
// Step 6: The Payer extracts the Signer's Nostr signature
// -------------------------------

// After retrieving the complete signature from the Cashu Mint (NIP-7),
// the Payer extracts the Signer's secret (Nostr event signature)
let extractedSecret = (s_c - s_a + secp.CURVE.n) % secp.CURVE.n;
console.log(
  "Extracted Secret (t = s_c - s_a):",
  extractedSecret.toString(16),
  "\n"
);

// And can now publish the signed Nostr event to the network
const nostrSignature = Buffer.concat([
  R_s_x, // Signer's public nonce shared in Step 2
  Buffer.from(extractedSecret.toString(16).padStart(64, "0"), "hex"),
]).toString("hex");

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
