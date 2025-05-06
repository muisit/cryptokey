import { CryptoKey } from "./CryptoKey";
import { x25519 } from "@noble/curves/ed25519";
import { toString } from "uint8arrays";

/*
 * Curve25519 is an elliptic curve designed for use in the Diffie-Hellman key agreement scheme (ECDH).
 * https://en.wikipedia.org/wiki/Curve25519
 *
 * https://www.amazon.science/blog/better-performing-25519-elliptic-curve-cryptography
 * The x25519 algorithm is a key agreement algorithm, used to securely establish a shared secret between two peers.
 *
 * Hence, although the key is supported in this library, it is not usable for signing or verification.
 */

export class X25519 extends CryptoKey {
  constructor() {
    super();
    this.keyType = "X25519";
  }

  createPrivateKey() {
    this.initialisePrivateKey(x25519.utils.randomPrivateKey());
  }

  initialisePrivateKey(key: any): void {
    this.privateKeyBytes = key;
    this.publicKeyBytes = x25519.getPublicKey(this.privateKeyBytes!);
  }

  toJWK() {
    return {
      kty: "OKP",
      crv: "X25519",
      kid: this.bytesToHex(this.publicKey()),
      use: "enc",
      key_ops: ["encrypt"],
      x: toString(this.publicKeyBytes!, "base64url"),
    };
  }

  importFromJWK(jwk: JsonWebKey) {
    if (jwk.kty == "OKP" && jwk.crv == "X25519" && jwk.x) {
      this.publicKeyBytes = this.base64UrlToBytes(jwk.x);
    }
  }

  algorithms() {
    return [];
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async signBytes(algorithm: string, data: Uint8Array) {
    throw new Error(
      "Algorithm " + algorithm + " not supported on key type " + this.keyType,
    );
    return new Uint8Array();
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async verify(algorithm: string, signature: Uint8Array, data: Uint8Array) {
    throw new Error(
      "Algorithm " + algorithm + " not supported on key type " + this.keyType,
    );
    return false;
  }
}
