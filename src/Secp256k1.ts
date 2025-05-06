import { CryptoKey } from "./CryptoKey";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import * as crypto from "node:crypto";
import { JsonWebKey } from "did-jwt/lib/util";
import { toString } from "uint8arrays";

export class Secp256k1 extends CryptoKey {
  constructor() {
    super();
    this.keyType = "Secp256k1";
  }

  createPrivateKey() {
    const key = crypto.createECDH("secp256k1");
    key.generateKeys();
    this.initialisePrivateKey(this.hexToBytes(key.getPrivateKey("hex")));
  }

  initialisePrivateKey(key: any): void {
    const secpkey = crypto.createECDH("secp256k1");
    secpkey.setPrivateKey(key);
    this.privateKeyBytes = key;
    this.publicKeyBytes = this.hexToBytes(
      secpkey.getPublicKey("hex", "compressed"),
    );
  }

  compressedToUncompressed(key: Uint8Array) {
    const point = secp256k1.ProjectivePoint.fromHex(this.bytesToHex(key));
    const uncompressedHex = point.toHex(false);
    return this.hexToBytes(uncompressedHex);
  }

  toJWK(): crypto.JsonWebKey {
    const uncompressed = this.compressedToUncompressed(this.publicKey());
    return {
      kty: "EC",
      crv: "secp256k1",
      kid: this.bytesToHex(this.publicKey()),
      use: "sig",
      key_ops: ["verify"],
      alg: "ES256",
      x: toString(uncompressed.slice(1, 33), "base64url"),
      y: toString(uncompressed.slice(33), "base64url"),
    };
  }

  importFromJWK(jwk: JsonWebKey) {
    if (jwk.kty == "EC" && jwk.crv == "secp256k1" && jwk.x && jwk.y) {
      const uncompressed = new Uint8Array(65);
      uncompressed.set([0x04], 0);
      uncompressed.set(this.base64UrlToBytes(jwk.x), 1);
      uncompressed.set(this.base64UrlToBytes(jwk.y), 33);
      this.publicKeyBytes =
        secp256k1.ProjectivePoint.fromHex(uncompressed).toRawBytes(true);
    }
  }

  algorithms() {
    return ["ES256K", "ES256K-R"];
  }

  async signBytes(algorithm: string, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }

    const msgHash = sha256(data);
    const signature = secp256k1.sign(msgHash, this.privateKey());

    if (algorithm == "ES256K-R") {
      const signatureWithRecovery = new Uint8Array(65);
      signatureWithRecovery.set(signature.toCompactRawBytes(), 0);
      signatureWithRecovery[64] = signature.recovery;
      return signatureWithRecovery;
    }
    return signature.toCompactRawBytes();
  }

  async verify(algorithm: string, signature: Uint8Array, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }

    const messageHash = sha256(data);
    let isValid = false;
    if (algorithm == "ES256K-R") {
      signature = signature.slice(0, 64);
    }

    isValid = secp256k1.verify(signature, messageHash, this.publicKey());

    if (isValid) {
      return true;
    }
    return false;
  }
}
