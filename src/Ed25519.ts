import { CryptoKey } from "./CryptoKey";
import { ed25519 } from "@noble/curves/ed25519";
import * as crypto from "node:crypto";
import { toString } from "uint8arrays";

export class Ed25519 extends CryptoKey {
  constructor() {
    super();
    this.keyType = "Ed25519";
  }

  createPrivateKey() {
    this.initialisePrivateKey(ed25519.utils.randomPrivateKey());
  }

  initialisePrivateKey(keyData?: Uint8Array): void {
    this.privateKeyBytes = keyData ?? ed25519.utils.randomPrivateKey();
    if (this.privateKeyBytes!.length > 32) {
      // precaution in case we have a priv+pub key concatenation
      this.privateKeyBytes = this.privateKeyBytes!.slice(0, 32);
    }
    this.publicKeyBytes = ed25519.getPublicKey(this.privateKeyBytes!);
  }

  toJWK(): crypto.JsonWebKey {
    return {
      kty: "OKP",
      crv: "Ed25519",
      kid: this.bytesToHex(this.publicKey()),
      use: "sig",
      key_ops: ["verify"],
      alg: "EdDSA",
      x: toString(this.publicKey(), "base64url"),
    };
  }

  importFromJWK(jwk: JsonWebKey) {
    if (jwk.kty == "OKP" && jwk.crv == "Ed25519" && jwk.x) {
      this.publicKeyBytes = this.base64UrlToBytes(jwk.x);
    }
  }

  algorithms() {
    return ["EdDSA", "Ed25519"];
  }

  async signBytes(algorithm: string, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }
    return ed25519.sign(data, this.privateKey());
  }

  async verify(algorithm: string, signature: Uint8Array, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }

    const isValid = ed25519.verify(signature, data, this.publicKey());
    if (isValid) {
      return true;
    }
    return false;
  }
}
