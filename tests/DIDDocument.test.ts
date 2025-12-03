import { test, expect } from "vitest";
import { Secp256r1 } from "../src/Secp256r1";
import * as crypto from "node:crypto";
import { Factory } from "../src/Factory";
import { CryptoKey } from "../src/CryptoKey";
import { ec } from "elliptic";
import { toString, fromString } from "uint8arrays";

const privkeyhex =
  "44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11";

test("Create document", async () => {
  const key = await Factory.createFromType("Secp256r1", privkeyhex);
  const doc = await Factory.toDIDDocument(key);
  expect(doc).toBeDefined();
  expect((doc["@context"] ?? [])[0]).toBe("https://www.w3.org/ns/did/v1");
  expect(doc.id).toBe(
    "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoieHVKNUxKdmdZNWFnZUJVYnlKNXZWVFFTeXJBQXgteHh4Ym1TazROVzJZQSIsInkiOiJaSHVqWXItSGhObVZydGRmNGljenRDTTJlTUo2WENxNDJNd3d1aGtENmRFIn0",
  );
  expect(doc.verificationMethod!.length).toBe(1);
  expect(doc.verificationMethod![0].id).toBe(
    "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoieHVKNUxKdmdZNWFnZUJVYnlKNXZWVFFTeXJBQXgteHh4Ym1TazROVzJZQSIsInkiOiJaSHVqWXItSGhObVZydGRmNGljenRDTTJlTUo2WENxNDJNd3d1aGtENmRFIn0#0",
  );
  expect(doc.verificationMethod![0].type).toBe("JsonWebKey");
  expect(doc.verificationMethod![0].controller).toBe(doc.id);
  expect(doc.authentication!.length).toBe(1);
  expect(doc.authentication![0]).toBe("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoieHVKNUxKdmdZNWFnZUJVYnlKNXZWVFFTeXJBQXgteHh4Ym1TazROVzJZQSIsInkiOiJaSHVqWXItSGhObVZydGRmNGljenRDTTJlTUo2WENxNDJNd3d1aGtENmRFIn0#0");
  expect(doc.assertionMethod!.length).toBe(1);
  expect(doc.assertionMethod![0]).toBe("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoieHVKNUxKdmdZNWFnZUJVYnlKNXZWVFFTeXJBQXgteHh4Ym1TazROVzJZQSIsInkiOiJaSHVqWXItSGhObVZydGRmNGljenRDTTJlTUo2WENxNDJNd3d1aGtENmRFIn0#0");
  expect(doc.capabilityDelegation!.length).toBe(1);
  expect(doc.capabilityDelegation![0]).toBe("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoieHVKNUxKdmdZNWFnZUJVYnlKNXZWVFFTeXJBQXgteHh4Ym1TazROVzJZQSIsInkiOiJaSHVqWXItSGhObVZydGRmNGljenRDTTJlTUo2WENxNDJNd3d1aGtENmRFIn0#0");
  expect(doc.capabilityInvocation!.length).toBe(1);
  expect(doc.capabilityInvocation![0]).toBe("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoieHVKNUxKdmdZNWFnZUJVYnlKNXZWVFFTeXJBQXgteHh4Ym1TazROVzJZQSIsInkiOiJaSHVqWXItSGhObVZydGRmNGljenRDTTJlTUo2WENxNDJNd3d1aGtENmRFIn0#0");
  expect(doc.service).toBeUndefined();
});

test("Create document with did", async () => {
  const key = await Factory.createFromType("Secp256r1", privkeyhex);
  const doc = await Factory.toDIDDocument(key, "did:web:some.example.net");
  expect(doc).toBeDefined();
  expect(doc.id).toBe("did:web:some.example.net");
  expect(doc.verificationMethod!.length).toBe(1);
  expect(doc.verificationMethod![0].id).toBe("did:web:some.example.net#0");
  expect(doc.verificationMethod![0].controller).toBe(doc.id);
  expect(doc.authentication!.length).toBe(1);
  expect(doc.authentication![0]).toBe("did:web:some.example.net#0");
});

test("Create document with did", async () => {
  const key = await Factory.createFromType("Secp256r1", privkeyhex);
  const doc = await Factory.toDIDDocument(key, "did:web:some.example.net");
  expect(doc).toBeDefined();
  expect(doc.id).toBe("did:web:some.example.net");
  expect(doc.verificationMethod!.length).toBe(1);
  expect(doc.verificationMethod![0].id).toBe("did:web:some.example.net#0");
  expect(doc.verificationMethod![0].controller).toBe(doc.id);
  expect(doc.authentication!.length).toBe(1);
  expect(doc.authentication![0]).toBe("did:web:some.example.net#0");
});

test("Create document with alternative verification method", async () => {
  const key = await Factory.createFromType("Secp256r1", privkeyhex);
  const doc = await Factory.toDIDDocument(
    key,
    "did:web:some.example.net",
    null,
    "JsonWebkey2020",
  );
  expect(doc).toBeDefined();
  expect(doc.id).toBe("did:web:some.example.net");
  expect(doc.verificationMethod!.length).toBe(1);
  expect(doc.verificationMethod![0].id).toBe("did:web:some.example.net#0");
  expect(doc.verificationMethod![0].type).toBe("JsonWebkey2020");
  expect(doc.verificationMethod![0].controller).toBe(doc.id);
  expect(doc.authentication!.length).toBe(1);
  expect(doc.authentication![0]).toBe("did:web:some.example.net#0");
});

test("Create document with services", async () => {
  const key = await Factory.createFromType("Secp256r1", privkeyhex);
  const services = [
    {
      id: "my:id",
      type: "LinkedDomains",
      endpoint: "somewhere",
    },
    {
      id: "another.id",
      type: "OIDCIssuance",
      endpoint: "there",
    },
  ];
  const doc = await Factory.toDIDDocument(
    key,
    "did:web:some.example.net",
    services,
  );
  expect(doc).toBeDefined();
  expect(doc.service).toBeDefined();
  expect(doc.service!.length).toBe(2);
  expect(doc.service![0].id).toBe("my:id");
  expect(doc.service![0].endpoint).toBe("somewhere");
  expect(doc.service![1].id).toBe("another.id");
  expect(doc.service![1].endpoint).toBe("there");
});
