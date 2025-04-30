import {
  contextFromKeyFormat,
  CryptoKey,
  SupportedVerificationMethods,
} from "./CryptoKey";
import { multibaseToBytes, bytesToBase58 } from "@veramo/utils";
import {
  DIDDocument,
  DIDResolutionResult,
  VerificationMethod,
} from "did-resolver";
import { ed25519 } from "@noble/curves/ed25519";
import { JsonWebKey } from "did-jwt/lib/util";
import * as crypto from "node:crypto";

export class Ed25519 extends CryptoKey {
  constructor() {
    super();
    this.keyType = "Ed25519";
    this.codecCode = 0xed;
  }

  createPrivateKey() {
    this.initialisePrivateKey(ed25519.utils.randomPrivateKey());
  }

  initialisePrivateKey(keyData?: Uint8Array): void {
    this.privateKeyBytes = keyData ?? ed25519.utils.randomPrivateKey();
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
      x: Buffer.from(this.publicKeyBytes!).toString("base64url"),
    };
  }

  importFromJWK(jwk: JsonWebKey) {
    if (jwk.kty == "OKP" && jwk.crv == "Ed25519" && jwk.x) {
      this.publicKeyBytes = this.base64UrlToBytes(jwk.x);
    }
  }

  importFromDid(didKey: string): void {
    if (!didKey.startsWith("did:key:z6Mk")) {
      throw new Error("Ed25519 did:key must start with did:key:z6Mk prefix");
    }

    const keyMultibase = didKey.substring(8);
    const result = multibaseToBytes(keyMultibase);
    if (!result.keyType || result.keyType !== "Ed25519") {
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

    //let keyAgreementKeyFormat:SupportedVerificationMethods = publicKeyFormat;
    switch (publicKeyFormat) {
      case SupportedVerificationMethods.JsonWebKey2020:
        verificationMethod.publicKeyJwk = this.toJWK() as JsonWebKey;
        break;
      case SupportedVerificationMethods.Multikey:
        verificationMethod.publicKeyMultibase = keyMultibase;
        break;
      case SupportedVerificationMethods.Ed25519VerificationKey2020:
        //keyAgreementKeyFormat = SupportedVerificationMethods.X25519KeyAgreementKey2020;
        verificationMethod.publicKeyMultibase = keyMultibase;
        break;
      case SupportedVerificationMethods.Ed25519VerificationKey2018:
        //keyAgreementKeyFormat = SupportedVerificationMethods.X25519KeyAgreementKey2019;
        verificationMethod.publicKeyBase58 = bytesToBase58(this.publicKey());
        break;
      default:
        throw new Error(
          `invalidPublicKeyType: Unsupported public key format ${publicKeyFormat}`,
        );
    }

    const ldContextArray: any[] = [
      "https://www.w3.org/ns/did/v1",
      contextFromKeyFormat[publicKeyFormat.toString()],
    ];

    const result: DIDResolutionResult = {
      didResolutionMetadata: {},
      didDocumentMetadata: { contentType: "application/did+ld+json" },
      didDocument: {
        id: did,
        verificationMethod: [verificationMethod],
        authentication: [verificationMethod.id],
        assertionMethod: [verificationMethod.id],
        capabilityDelegation: [verificationMethod.id],
        capabilityInvocation: [verificationMethod.id],
      },
    };

    let ldContext = {};
    const acceptedFormat: string = "application/did+ld+json";
    if (acceptedFormat === "application/did+json") {
      ldContext = {};
    } else if (acceptedFormat === "application/did+ld+json") {
      ldContext = { "@context": ldContextArray };
    } else {
      throw new Error(
        `unsupportedFormat: The DID resolver does not support the requested 'accept' format: ${acceptedFormat}`,
      );
    }

    result.didDocument = { ...result.didDocument, ...ldContext } as DIDDocument;

    return result;
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

    const isValid = ed25519.verify(
      signature,
      Buffer.from(data),
      this.publicKey(),
    );
    if (isValid) {
      return true;
    }
    return false;
  }
}
