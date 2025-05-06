import { CryptoKey } from "../CryptoKey";
import { contextFromKeyFormat, VerificationMethods } from "../types";
import {
  DIDDocument,
  VerificationMethod,
  JsonWebKey as JsonWebKeyDID,
} from "did-resolver";
import { convertToDIDKey, convertToMultibase } from "./convertDIDKey";
import { convertToDIDJWK } from "./convertDIDJWK";
import { Factory } from "../Factory";

// https://www.w3.org/TR/did-1.0/
export function convertToDidDocument(
  key: CryptoKey,
  publicKeyFormat: VerificationMethods = VerificationMethods.JsonWebKey,
  verificationMethodType?: string,
  did?: string,
) {
  let verificationMethod: VerificationMethod;

  //let keyAgreementKeyFormat:SupportedVerificationMethods = publicKeyFormat;
  switch (publicKeyFormat) {
    case VerificationMethods.JsonWebKey:
      did = did || convertToDIDJWK(key);
      verificationMethod = {
        // did:jwk spec defines that the key is referenced as #0
        id: did + "#0",
        // there is a discontinued vc-jws spec that defines JsonWebKey2020, but it is the same
        type: verificationMethodType || "JsonWebKey",
        publicKeyJwk: key.toJWK() as JsonWebKeyDID,
        controller: did,
      };
      break;
    case VerificationMethods.Multikey:
      did = did || convertToDIDKey(key);
      verificationMethod = {
        // did:key spec defines that the key is referenced with the multi-codec-value
        id: did + "#" + convertToMultibase(key),
        type: verificationMethodType || "Multikey",
        publicKeyMultibase: convertToMultibase(key),
        controller: did,
      };
      break;
    default:
      throw new Error(
        `invalidPublicKeyType: Unsupported public key format ${publicKeyFormat}`,
      );
  }

  let ldContextArray: any[] = ["https://www.w3.org/ns/did/v1"];

  if (verificationMethodType && contextFromKeyFormat[verificationMethodType]) {
    ldContextArray = ldContextArray.concat(
      contextFromKeyFormat[verificationMethodType],
    );
  }

  let result: DIDDocument = {
    "@context": ldContextArray,
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [verificationMethod.id],
    assertionMethod: [verificationMethod.id],
    capabilityDelegation: [verificationMethod.id],
    capabilityInvocation: [verificationMethod.id],
  };

  // X25519 keys are only used for key agreements
  if (key.keyType == "X25519") {
    result = {
      id: did,
      verificationMethod: [verificationMethod],
      keyAgreement: [verificationMethod.id],
    };
  }

  return result;
}

export function convertFromDIDDocument(doc: DIDDocument) {
  if (doc["verificationMethod"]) {
    // just pick the first we understand
    for (const methods of doc["verificationMethod"]) {
      if (methods.publicKeyJwk) {
        return Factory.createFromJWK(methods.publicKeyJwk);
      } else if (methods.publicKeyMultibase) {
        return Factory.createFromDIDKey(
          "did:key:" + methods.publicKeyMultibase,
        );
      }
    }
  }
  throw new Error("No key found in DID document");
}
