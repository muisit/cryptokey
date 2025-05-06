import { CryptoKey } from "./CryptoKey";
import { Ed25519 } from "./Ed25519";
import { X25519 } from "./X25519";
import { Secp256r1 } from "./Secp256r1";
import { Secp256k1 } from "./Secp256k1";
import { ManagedKeyInfo } from "@veramo/core-types";
import { convertFromDIDKey, convertToDIDKey } from "./convertors/convertDIDKey";
import { convertFromJWK } from "./convertors/convertJWK";
import { convertFromDIDJWK, convertToDIDJWK } from "./convertors/convertDIDJWK";
import { convertFromDIDWeb } from "./convertors/convertDIDWeb";

export class Factory {
  public static createFromType(
    keyType: string,
    privateKeyHex?: string,
  ): CryptoKey {
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
      default:
        throw new Error("key type " + keyType + " notsupported");
    }

    if (privateKeyHex) {
      key.initialisePrivateKey(key.hexToBytes(privateKeyHex));
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

  public static async createFromDIDWeb(didUrl: string): Promise<CryptoKey> {
    return await convertFromDIDWeb(didUrl);
  }

  public static createFromDIDKey(didKey: string): CryptoKey {
    return convertFromDIDKey(didKey)!;
  }
  public static toDIDKey(key: CryptoKey): string {
    return convertToDIDKey(key);
  }

  public static createFromDIDJWK(didKey: string): CryptoKey {
    return convertFromDIDJWK(didKey)!;
  }
  public static toDIDJWK(key: CryptoKey): string {
    return convertToDIDJWK(key);
  }

  public static createFromManagedKey(mkey: ManagedKeyInfo): CryptoKey {
    let key: CryptoKey;
    switch ((mkey.type as string).toLowerCase()) {
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
      default:
        throw new Error("key type " + mkey.type + " not supported");
    }

    key.importFromManagedKey(mkey);
    return key;
  }

  public static createFromJWK(jwk: JsonWebKey): CryptoKey {
    return convertFromJWK(jwk);
  }

  public static toJWK(key: CryptoKey) {
    return key.toJWK();
  }
}
