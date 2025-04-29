import {
  contextFromKeyFormat,
  CryptoKey,
  SupportedVerificationMethods
} from "./CryptoKey";
import { multibaseToBytes, createJWK } from "@veramo/utils";
import { VerificationMethod } from "did-resolver";
import { createECDH, sign, verify } from "node:crypto";
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

export class Secp256k1 extends CryptoKey {
  constructor() {
    super();
    this.keyType = "Secp256k1";
    this.codecCode = 0xe7;
  }

  createPrivateKey() {
    const key = createECDH("secp256k1");
    key.generateKeys();
    this.initialisePrivateKey(this.hexToBytes(key.getPrivateKey("hex")));
  }

  initialisePrivateKey(key: any): void {
    const secpkey = createECDH("secp256k1");
    secpkey.setPrivateKey(key);
    this.privateKeyBytes = key;
    this.publicKeyBytes = this.hexToBytes(
      secpkey.getPublicKey("hex", "compressed"),
    );
  }

  compressedToUncompressed(key:Uint8Array) {
    const point = secp256k1.ProjectivePoint.fromHex(this.bytesToHex(key));
    const uncompressedHex = point.toHex(false);
    return this.hexToBytes(uncompressedHex);
  }

  toJWK() {
    return {
      kty: "EC",
      crv: "secp256k1",
      x: Buffer.from(this.publicKeyBytes!.slice(1, 33)).toString("base64url"),
      y: Buffer.from(this.publicKeyBytes!.slice(33)).toString("base64url"),
    };
  }

  importFromDid(didKey: string): void {
    if (
      !didKey.startsWith("did:key:zQ3s") &&
      !didKey.startsWith("did:key:z7r8")
    ) {
      throw new Error(
        "Secp256k1 did:key must start with did:key:zQ3s or did:key:z7r8 prefix",
      );
    }

    const keyMultibase = didKey.substring(8);
    const result = multibaseToBytes(keyMultibase);
    const resultKeyType: string | undefined = result.keyType?.toString();
    if (
      !resultKeyType ||
      (resultKeyType !== "P-256" && resultKeyType !== "Secp256k1")
    ) {
      throw new Error(
        `invalidDid: the key type cannot be deduced for ${didKey}`,
      );
    }
    this.publicKeyBytes = result.keyBytes;
  }

  didDocument(method?: SupportedVerificationMethods) {
    const publicKeyFormat: SupportedVerificationMethods =
      method || SupportedVerificationMethods.JsonWebKey2020;

    const keyMultibase = this.toDIDKey();
    const did = "did:key:" + keyMultibase;
    const verificationMethod: VerificationMethod = {
      id: `${did}#${keyMultibase}`,
      type: publicKeyFormat.toString(),
      controller: did,
    };

    switch (publicKeyFormat) {
      case SupportedVerificationMethods.JsonWebKey2020:
      case SupportedVerificationMethods.EcdsaSecp256r1VerificationKey2019:
        verificationMethod.publicKeyJwk = createJWK(
          "Secp256k1",
          this.publicKey(),
          "sig",
        );
        break;
      case SupportedVerificationMethods.Multikey:
      case SupportedVerificationMethods.EcdsaSecp256k1VerificationKey2019:
      case SupportedVerificationMethods.EcdsaSecp256k1VerificationKey2020:
        verificationMethod.publicKeyMultibase = keyMultibase;
        break;
      default:
        throw new Error(
          `invalidPublicKeyType: Unsupported public key format ${publicKeyFormat}`,
        );
    }

    let ldContext = {};
    const acceptedFormat: string = "application/did+ld+json";
    if (acceptedFormat === "application/did+json") {
      ldContext = {};
    } else if (acceptedFormat === "application/did+ld+json") {
      ldContext = {
        "@context": [
          "https://www.w3.org/ns/did/v1",
          contextFromKeyFormat[publicKeyFormat],
        ],
      };
    } else {
      throw new Error(
        `unsupportedFormat: The DID resolver does not support the requested 'accept' format: ${acceptedFormat}`,
      );
    }

    return {
      didResolutionMetadata: {},
      didDocumentMetadata: { contentType: "application/did+ld+json" },
      didDocument: {
        ...ldContext,
        id: did,
        verificationMethod: [verificationMethod],
        authentication: [verificationMethod.id],
        assertionMethod: [verificationMethod.id],
        capabilityDelegation: [verificationMethod.id],
        capabilityInvocation: [verificationMethod.id],
      },
    };
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
      return new Uint8Array([...schnorr.utils.numberToBytesBE(signature.r, 32), ...schnorr.utils.numberToBytesBE(signature.s, 32), signature.recovery]);
    }
    return new Uint8Array([...schnorr.utils.numberToBytesBE(signature.r, 32), ...schnorr.utils.numberToBytesBE(signature.s, 32)]);
  }

  async verify(algorithm:string, signature:string, data:Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }

    try {
      const messageHash = sha256(data);
      const isValid = secp256k1.verify(this.hexToBytes(signature), messageHash, this.publicKey());
      if (isValid) {
        return true;
      }
    }
    catch (e) {

    }
    return false;
  }
}
