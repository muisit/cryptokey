import {
  contextFromKeyFormat,
  CryptoKey,
  SupportedVerificationMethods,
} from "./CryptoKey";
import { ed25519 } from "@noble/curves/ed25519";
import { EdDSASigner } from "did-jwt";
import { multibaseToBytes, bytesToBase58, createJWK } from "@veramo/utils";
import {
  DIDDocument,
  DIDResolutionResult,
  VerificationMethod,
} from "did-resolver";
import { fromString, toString } from 'uint8arrays'

export class Ed25519 extends CryptoKey {
  constructor() {
    super();
    this.keyType = "Ed25519";
    this.codecCode = 0xed;
  }

  createPrivateKey() {
    this.initialisePrivateKey(ed25519.utils.randomPrivateKey());
  }

  initialisePrivateKey(key?: Uint8Array): void {
    this.privateKeyBytes = key ?? ed25519.utils.randomPrivateKey();
    this.publicKeyBytes = ed25519.getPublicKey(this.privateKeyBytes);
  }

  toJWK() {
    return {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(this.publicKeyBytes!).toString("base64url"),
    };
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
        verificationMethod.publicKeyJwk = createJWK(
          this.keyType as any,
          this.publicKey(),
          "sig",
        );
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
    const signer = EdDSASigner(this.privateKey());
    const signature = await signer(data);
    // base64url encoded string
    return fromString(signature as string, 'base64url');
  }
}
