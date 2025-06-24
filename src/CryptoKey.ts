import { fromString, toString } from "uint8arrays";
import * as crypto from "node:crypto";

export abstract class CryptoKey {
  public keyType: string;
  public privateKeyBytes: Uint8Array | null;
  public publicKeyBytes: Uint8Array | null;

  constructor() {
    this.keyType = "none";
    this.privateKeyBytes = null;
    this.publicKeyBytes = null;
  }

  abstract createPrivateKey(): Promise<void>;
  abstract algorithms(): string[];
  abstract importFromJWK(jwk: JsonWebKey): Promise<void>;

  abstract signBytes(algorithm: string, data: Uint8Array): Promise<Uint8Array>;
  async sign(
    algorithm: string,
    data: Uint8Array,
    encode: string = "raw",
  ): Promise<string> {
    const signature = await this.signBytes(algorithm, data);
    switch (encode) {
      default:
      case "raw":
        break;
      case "base16":
      case "hex":
        return toString(signature, "base16");
      case "base58btc":
        return toString(signature, "base58btc");
      case "base64":
        return toString(signature, "base64");
      case "base64url":
        return toString(signature, "base64url");
    }
    throw new Error("unable to encode resulting signature using " + encode);
  }

  abstract verify(
    algorithm: string,
    signature: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean>;

  async initialisePrivateKey(key: any) {
    this.privateKeyBytes = key;
  }

  public static bytesToHex(bytes: Uint8Array): string {
    return toString(bytes, "base16");
  }
  public static hexToBytes(buffer: string): Uint8Array {
    let input = buffer.startsWith("0x") ? buffer.substring(2) : buffer;

    if (input.length % 2 !== 0) {
      input = `0${input}`;
    }
    return fromString(input, "base16");
  }
  public static bytesToBase64(bytes: Uint8Array, doPad = false): string {
    const retval: string = toString(bytes, "base64");
    if (doPad) {
      const missingPadding = (4 - (retval.length % 4)) % 4;
      return retval + "=".repeat(missingPadding);
    }
    return retval;
  }
  public static base64ToBytes(buffer: string) {
    return fromString(buffer, "base64");
  }
  public static bytesToBase64Url(bytes: Uint8Array): string {
    return toString(bytes, "base64url");
  }
  public static base64UrlToBytes(buffer: string) {
    return fromString(buffer, "base64url");
  }

  hasPublicKey(): boolean {
    return this.publicKeyBytes !== null && this.publicKeyBytes.length > 0;
  }
  publicKey(): Uint8Array {
    return this.publicKeyBytes ?? new Uint8Array();
  }
  exportPublicKey(): string {
    return CryptoKey.bytesToHex(this.publicKey());
  }
  setPublicKey(publicKeyHex: string) {
    this.publicKeyBytes = CryptoKey.hexToBytes(publicKeyHex);
  }

  hasPrivateKey(): boolean {
    return this.privateKeyBytes !== null && this.privateKeyBytes.length > 0;
  }
  privateKey(): Uint8Array {
    return this.privateKeyBytes ?? new Uint8Array();
  }
  exportPrivateKey(): string {
    return CryptoKey.bytesToHex(this.privateKey());
  }
  setPrivateKey(privateKeyHex: string) {
    this.privateKeyBytes = CryptoKey.hexToBytes(privateKeyHex);
  }

  // creating a JWK is very key specific, but straight forward, so no reason to abstract in a convertor
  abstract toJWK(alg?: string): Promise<crypto.JsonWebKey>;
}
