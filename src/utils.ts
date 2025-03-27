import { Proof } from "@cashu/cashu-ts";
import { schnorr, secp256k1 as secp } from "@noble/curves/secp256k1";
import { randomBytes } from "@noble/hashes/utils";

export function negateScalar(scalar: Uint8Array): Uint8Array {
  const s = BigInt("0x" + Buffer.from(scalar).toString("hex"));
  const negated = (secp.CURVE.n - s) % secp.CURVE.n;
  return Buffer.from(negated.toString(16).padStart(64, "0"), "hex");
}

export function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function decomposePowersOfTwo(n: number): number[] {
  return Array.from({ length: Math.floor(Math.log2(n)) + 1 })
    .map((_, i) => Math.pow(2, i))
    .filter((power) => (n & power) !== 0);
}

export function mockProofs(fullAmount: number, pubkey: string): Proof[] {
  const mockKeysetId = Buffer.from(randomBytes(16)).toString("hex");
  return decomposePowersOfTwo(fullAmount).map((amount) => {
    return {
      amount,
      secret: JSON.stringify([
        "P2PK",
        {
          nonce: Buffer.from(schnorr.utils.randomPrivateKey()).toString("hex"),
          data: pubkey,
        },
      ]),
      id: mockKeysetId,
      C: Buffer.from(randomBytes(32)).toString("hex"),
    };
  });
}
