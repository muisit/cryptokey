import { CryptoKey } from "./CryptoKey";
import { Ed25519 } from "./Ed25519";
import { X25519 } from "./X25519";
import { Secp256r1 } from "./Secp256r1";
import { Secp256k1 } from "./Secp256k1";
import { RSA } from "./RSA";
import { convertFromDIDKey, convertToDIDKey } from "./convertors/convertDIDKey";
import { convertFromJWK } from "./convertors/convertJWK";
import { convertFromDIDJWK, convertToDIDJWK } from "./convertors/convertDIDJWK";
import { convertFromDIDWeb } from "./convertors/convertDIDWeb";
import {
  convertFromDIDDocument,
  convertToDIDDocument,
} from "./convertors/convertDIDDocument";
import { VerificationMethods } from "./types";

export class Factory {
  public static async createFromType(
    keyType: string,
    privateKeyHex?: string,
  ): Promise<CryptoKey> {
    let key: CryptoKey;
    switch (keyType.toLocaleLowerCase()) {
      case "ed25519":
        key = new Ed25519();
        break;
      case "x25519":
        key = new X25519();
        break;
      case "secp256r1":
        key = new Secp256r1();
        break;
      case "secp256k1":
        key = new Secp256k1();
        break;
      case "rsa":
        key = new RSA();
        break;
      default:
        throw new Error("key type " + keyType + " notsupported");
    }

    if (privateKeyHex) {
      await key.initialisePrivateKey(CryptoKey.hexToBytes(privateKeyHex));
    }
    return key;
  }

  public static async resolve(keyId: string) {
    if (keyId.startsWith("did:key:")) {
      return Factory.createFromDIDKey(keyId);
    } else if (keyId.startsWith("did:jwk:")) {
      return Factory.createFromDIDJWK(keyId);
    } else if (keyId.startsWith("did:web:")) {
      return await Factory.createFromDIDWeb(keyId);
    }
    throw new Error("Cannot resolve " + keyId);
  }

  public static getKeyReference(keyId: string) {
    if (keyId.startsWith("did:key:")) {
      return keyId.substring(8); // according to the spec, the reference is the multibase encoded public key
    } else if (keyId.startsWith("did:jwk:")) {
      return "0"; // by definition in the spec
    } else if (keyId.startsWith("did:web:")) {
      return "0"; // due to our implementation
    }
    throw new Error("Cannot resolve " + keyId);
  }

  public static async createFromDIDWeb(didUrl: string): Promise<CryptoKey> {
    return await convertFromDIDWeb(didUrl);
  }

  public static async createFromDIDKey(didKey: string): Promise<CryptoKey> {
    return await convertFromDIDKey(didKey)!;
  }
  public static async toDIDKey(key: CryptoKey): Promise<string> {
    return await convertToDIDKey(key);
  }

  public static async createFromDIDJWK(didKey: string): Promise<CryptoKey> {
    return await convertFromDIDJWK(didKey)!;
  }
  public static async toDIDJWK(key: CryptoKey): Promise<string> {
    return await convertToDIDJWK(key);
  }

  public static async createFromJWK(jwk: JsonWebKey): Promise<CryptoKey> {
    return await convertFromJWK(jwk);
  }

  public static async createFromDIDDocument(doc: any): Promise<CryptoKey> {
    return await convertFromDIDDocument(doc);
  }

  public static async toDIDDocument(
    key: CryptoKey,
    did?: string,
    services?: any,
    verificationMethodType: string = "JsonWebKey",
  ) {
    return await convertToDIDDocument(
      key,
      VerificationMethods.JsonWebKey,
      verificationMethodType,
      did,
      services,
    );
  }

  public static async toJWK(key: CryptoKey) {
    return await key.toJWK();
  }
}
