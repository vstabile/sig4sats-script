import { secp256k1 as secp } from "@noble/curves/secp256k1";

export function negateScalar(scalar: Uint8Array): Uint8Array {
  const s = BigInt("0x" + Buffer.from(scalar).toString("hex"));
  const negated = (secp.CURVE.n - s) % secp.CURVE.n;
  return Buffer.from(negated.toString(16).padStart(64, "0"), "hex");
}

export function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
