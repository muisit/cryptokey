import { CryptoKey } from "./CryptoKey";
import * as crypto from "node:crypto";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { JsonWebKey } from "did-jwt/lib/util";

/* NIST secp256r1 aka p256 aka prime256v1
 * https://www.secg.org/sec2-v2.pdf
 * https://neuromancer.sk/std/nist/P-256
 */
export class Secp256r1 extends CryptoKey {
  constructor() {
    super();
    this.keyType = "Secp256r1";
  }

  createPrivateKey() {
    const key = crypto.createECDH("prime256v1");
    key.generateKeys();
    this.initialisePrivateKey(this.hexToBytes(key.getPrivateKey("hex")));
  }

  initialisePrivateKey(key: any): void {
    const secpkey = crypto.createECDH("prime256v1");
    secpkey.setPrivateKey(key);
    this.privateKeyBytes = key;
    this.publicKeyBytes = this.hexToBytes(
      secpkey.getPublicKey("hex", "compressed"),
    );
  }

  compressedToUncompressed(key: Uint8Array) {
    const point = p256.ProjectivePoint.fromHex(this.bytesToHex(key));
    const uncompressedHex = point.toHex(false);
    return this.hexToBytes(uncompressedHex);
  }

  toJWK(): crypto.JsonWebKey {
    const uncompressed = this.compressedToUncompressed(this.publicKey());
    return {
      kty: "EC",
      crv: "P-256",
      kid: this.bytesToHex(this.publicKey()),
      use: "sig",
      key_ops: ["verify"],
      alg: "ES256",
      x: Buffer.from(uncompressed.slice(1, 33)).toString("base64url"),
      y: Buffer.from(uncompressed.slice(33)).toString("base64url"),
    };
  }

  importFromJWK(jwk: JsonWebKey) {
    if (jwk.kty == "EC" && jwk.crv == "P-256" && jwk.x && jwk.y) {
      const uncompressed = new Uint8Array(65);
      uncompressed.set([0x04], 0);
      uncompressed.set(this.base64UrlToBytes(jwk.x), 1);
      uncompressed.set(this.base64UrlToBytes(jwk.y), 33);
      this.publicKeyBytes =
        p256.ProjectivePoint.fromHex(uncompressed).toRawBytes(true);
    }
  }

  algorithms() {
    return ["ES256"];
  }

  async signBytes(algorithm: string, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }
    const messageHash = sha256(data);
    const signature = p256.sign(messageHash, this.privateKey());
    const rBytes = p256.CURVE.Fp.toBytes(signature.r); // 32 bytes
    const sBytes = p256.CURVE.Fp.toBytes(signature.s); // 32 bytes
    return new Uint8Array([...rBytes, ...sBytes]);
  }

  async verify(algorithm: string, signature: Uint8Array, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }

    const messageHash = sha256(data);
    const isValid = p256.verify(signature, messageHash, this.publicKey());
    if (isValid) {
      return true;
    }
    return false;
  }
}
