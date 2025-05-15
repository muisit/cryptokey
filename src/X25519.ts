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

  async createPrivateKey() {
    await this.initialisePrivateKey(x25519.utils.randomPrivateKey());
  }

  async initialisePrivateKey(key: any) {
    this.privateKeyBytes = key;
    if (this.privateKeyBytes!.length > 32) {
      // precaution in case we have a priv+pub key concatenation
      this.privateKeyBytes = this.privateKeyBytes!.slice(0, 32);
    }
    this.publicKeyBytes = x25519.getPublicKey(this.privateKeyBytes!);
  }

  async toJWK(alg?:string) {
    return {
      kty: "OKP",
      crv: "X25519",
      kid: this.bytesToHex(this.publicKey()),
      use: "enc",
      key_ops: ["encrypt"],
      x: toString(this.publicKeyBytes!, "base64url"),
    };
  }

  async importFromJWK(jwk: JsonWebKey) {
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
