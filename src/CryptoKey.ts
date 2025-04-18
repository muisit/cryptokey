import { fromString, toString } from "uint8arrays";
import { BaseName, encode } from "multibase";
import * as varint from "multiformats/varint";
import { IKey } from "@veramo/core-types";

export enum SupportedVerificationMethods {
  "JsonWebKey2020",
  "Multikey",
  "EcdsaSecp256k1VerificationKey2019", // deprecated,
  "EcdsaSecp256k1VerificationKey2020",
  "Ed25519VerificationKey2020",
  "Ed25519VerificationKey2018", // deprecated,
  "X25519KeyAgreementKey2020",
  "X25519KeyAgreementKey2019", // deprecated,
  "EcdsaSecp256r1VerificationKey2019",
}

export const contextFromKeyFormat: Record<string, string | object> = {
  JsonWebKey2020: "https://w3id.org/security/suites/jws-2020/v1",
  Multikey: "https://w3id.org/security/multikey/v1",
  EcdsaSecp256k1VerificationKey2020:
    "https://w3id.org/security/suites/secp256k1-2020/v1",
  EcdsaSecp256k1VerificationKey2019:
    "https://w3id.org/security/suites/secp256k1-2019/v1", // deprecated
  Ed25519VerificationKey2020:
    "https://w3id.org/security/suites/ed25519-2020/v1",
  Ed25519VerificationKey2018:
    "https://w3id.org/security/suites/ed25519-2018/v1", // deprecated
  X25519KeyAgreementKey2020: "https://w3id.org/security/suites/x25519-2020/v1",
  X25519KeyAgreementKey2019: "https://w3id.org/security/suites/x25519-2019/v1", // deprecated
  EcdsaSecp256r1VerificationKey2019: {
    EcdsaSecp256r1VerificationKey2019:
      "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019",
    publicKeyJwk: {
      "@id": "https://w3id.org/security#publicKeyJwk",
      "@type": "@json",
    },
  },
};

export interface JWK {
  kty: string;
  [x: string]: any;
}

export abstract class CryptoKey {
  public keyType: string;
  public privateKeyBytes: Uint8Array | null;
  public publicKeyBytes: Uint8Array | null;
  public codecCode: number = 0;
  public encodingBase: BaseName = "base58btc";

  constructor() {
    this.keyType = "none";
    this.privateKeyBytes = null;
    this.publicKeyBytes = null;
  }

  abstract createPrivateKey(): void;
  abstract algorithms(): string[];
  abstract toJWK(): JWK;
  abstract importFromDid(didKey: string): void;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  didDocument(method?: SupportedVerificationMethods): any {
    return {};
  }

  importFromManagedKey(mkey: IKey) {
    if (mkey.publicKeyHex) {
      this.publicKeyBytes = this.hexToBytes(mkey.publicKeyHex);
    }
    if (mkey.privateKeyHex) {
      this.privateKeyBytes = this.hexToBytes(mkey.privateKeyHex);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async sign(algorithm: string, data: Uint8Array): Promise<string> {
    throw new Error("sign not implemented for key of type " + this.keyType);
  }

  initialisePrivateKey(key: any) {
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

  publicKey(): Uint8Array {
    return this.publicKeyBytes ?? new Uint8Array();
  }

  publicKeyHex(): string {
    return this.bytesToHex(this.publicKeyBytes!);
  }
  setPublicKey(publicKeyHex: string) {
    this.publicKeyBytes = this.hexToBytes(publicKeyHex);
  }

  makeDidKeyIdentifier(): string {
    return this.bytesToMultibase(this.publicKey());
  }

  hasPublicKey(): boolean {
    return this.publicKeyBytes !== null && this.publicKeyBytes.length > 0;
  }
  hasPrivateKey(): boolean {
    return this.privateKeyBytes !== null && this.privateKeyBytes.length > 0;
  }
  exportPrivateKey(): string {
    return this.bytesToHex(this.privateKeyBytes!);
  }

  protected bytesToMultibase(b: Uint8Array, codecCode?: number) {
    if (!codecCode) {
      codecCode = this.codecCode;
    }
    const prefixLength = varint.encodingLength(codecCode);
    const multicodecEncoding = new Uint8Array(prefixLength + b.length);
    varint.encodeTo(codecCode, multicodecEncoding); // set prefix
    multicodecEncoding.set(b, prefixLength); // add the original bytes
    return toString(encode(this.encodingBase, multicodecEncoding), "utf-8");
  }
}
