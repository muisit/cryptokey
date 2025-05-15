import { fromString, toString } from "uint8arrays";
import { IKey } from "@veramo/core-types";
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

  async importFromManagedKey(mkey: IKey) {
    if (mkey.publicKeyHex) {
      this.publicKeyBytes = this.hexToBytes(mkey.publicKeyHex);
    }
    if (mkey.privateKeyHex) {
      this.privateKeyBytes = this.hexToBytes(mkey.privateKeyHex);
    }
  }

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

  public bytesToHex(bytes: Uint8Array): string {
    return toString(bytes, "base16");
  }
  public hexToBytes(buffer: string): Uint8Array {
    let input = buffer.startsWith("0x") ? buffer.substring(2) : buffer;

    if (input.length % 2 !== 0) {
      input = `0${input}`;
    }
    return fromString(input, "base16");
  }
  public bytesToBase64(bytes: Uint8Array): string {
    return toString(bytes, "base64");
  }
  public base64ToBytes(buffer: string) {
    return fromString(buffer, "base64");
  }
  public bytesToBase64Url(bytes: Uint8Array): string {
    return toString(bytes, "base64url");
  }
  public base64UrlToBytes(buffer: string) {
    return fromString(buffer, "base64url");
  }

  hasPublicKey(): boolean {
    return this.publicKeyBytes !== null && this.publicKeyBytes.length > 0;
  }
  publicKey(): Uint8Array {
    return this.publicKeyBytes ?? new Uint8Array();
  }
  exportPublicKey(): string {
    return this.bytesToHex(this.publicKey());
  }
  setPublicKey(publicKeyHex: string) {
    this.publicKeyBytes = this.hexToBytes(publicKeyHex);
  }

  hasPrivateKey(): boolean {
    return this.privateKeyBytes !== null && this.privateKeyBytes.length > 0;
  }
  privateKey(): Uint8Array {
    return this.privateKeyBytes ?? new Uint8Array();
  }
  exportPrivateKey(): string {
    return this.bytesToHex(this.privateKey());
  }
  setPrivateKey(privateKeyHex: string) {
    this.privateKeyBytes = this.hexToBytes(privateKeyHex);
  }

  // creating a JWK is very key specific, but straight forward, so no reason to abstract in a convertor
  abstract toJWK(alg?:string): Promise<crypto.JsonWebKey>;
}
