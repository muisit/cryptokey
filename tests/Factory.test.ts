import { test, expect } from "vitest";
import { Factory } from "../src/Factory";

test("create from did", async () => {
  let key1 = await Factory.createFromDIDKey(
    "did:key:z6Mkkf9RiKeaAFaQzQGT2zfqqwCYYbPTNhQvyGXjKJ84kW88",
  );
  expect(key1.keyType).toBe("Ed25519");
  expect(key1.exportPublicKey()).toBe(
    "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
  );
  expect(await Factory.toDIDKey(key1)).toBe(
    "did:key:z6Mkkf9RiKeaAFaQzQGT2zfqqwCYYbPTNhQvyGXjKJ84kW88",
  );

  let key2 = await Factory.createFromDIDKey(
    "did:key:zQ3shjZ5btPjB5qhUqJyH68XczxL11JqCTng4XBwhdy9nVYic",
  );
  expect(key2.keyType).toBe("Secp256k1");
  expect(key2.exportPublicKey()).toBe(
    "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  );
  expect(await Factory.toDIDKey(key2)).toBe(
    "did:key:zQ3shjZ5btPjB5qhUqJyH68XczxL11JqCTng4XBwhdy9nVYic",
  );

  let key3 = await Factory.createFromDIDKey(
    "did:key:zDnaew3eSC3JmvrFcgwgoGULgcm3iQR9han5k2d4P87vsDkdm",
  );
  expect(key3.keyType).toBe("Secp256r1");
  expect(key3.exportPublicKey()).toBe(
    "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
  );
  expect(await Factory.toDIDKey(key3)).toBe(
    "did:key:zDnaew3eSC3JmvrFcgwgoGULgcm3iQR9han5k2d4P87vsDkdm",
  );
});

test("create from jwk", async () => {
  let key1 = await Factory.createFromJWK({
    kty: "OKP",
    crv: "Ed25519",
    x: "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
  });
  expect(key1.keyType).toBe("Ed25519");
  expect(key1.exportPublicKey()).toBe(
    "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
  );
  expect((await Factory.toJWK(key1)).x).toBe(
    "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
  );

  let key2 = await Factory.createFromJWK({
    kty: "EC",
    crv: "secp256k1",
    x: "SQDOZtI0DqCJfHDQo_u4LBJboWP5WR7gkL4JehGtOfk",
    y: "LHYCNBRST2GGkpcnODzo4bPimyMEIwe9pK1S5Ssjh7s",
  });
  expect(key2.keyType).toBe("Secp256k1");
  expect(key2.exportPublicKey()).toBe(
    "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  );
  expect((await Factory.toJWK(key2)).x).toBe(
    "SQDOZtI0DqCJfHDQo_u4LBJboWP5WR7gkL4JehGtOfk",
  );

  let key3 = await Factory.createFromJWK({
    kty: "EC",
    crv: "P-256",
    x: "xuJ5LJvgY5ageBUbyJ5vVTQSyrAAx-xxxbmSk4NW2YA",
    y: "ZHujYr-HhNmVrtdf4icztCM2eMJ6XCq42MwwuhkD6dE",
  });
  expect(key3.keyType).toBe("Secp256r1");
  expect(key3.exportPublicKey()).toBe(
    "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
  );
  expect((await Factory.toJWK(key3)).x).toBe(
    "xuJ5LJvgY5ageBUbyJ5vVTQSyrAAx-xxxbmSk4NW2YA",
  );
});

test("DID:JWK", async () => {
  // this did:jwk does not contain alg and use claims
  const key1 = await Factory.createFromDIDJWK(
    "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlhER2JqQzFJQXlBbWMtMGFza3ZUUWx1UlRVSklHV2VzVE5rOHo4ZmV5emsifQ",
  );
  expect(key1.keyType).toBe("Ed25519");
  expect(key1.exportPublicKey()).toBe(
    "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
  );
  // we export with the alg and use claims included
  expect(await Factory.toDIDJWK(key1)).toBe(
    "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJ4IjoiWERHYmpDMUlBeUFtYy0wYXNrdlRRbHVSVFVKSUdXZXNUTms4ejhmZXl6ayJ9",
  );

  const key2 = await Factory.createFromDIDJWK(
    "did:jwk:eyJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiJTUURPWnRJMERxQ0pmSERRb191NExCSmJvV1A1V1I3Z2tMNEplaEd0T2ZrIiwieSI6IkxIWUNOQlJTVDJHR2twY25PRHpvNGJQaW15TUVJd2U5cEsxUzVTc2poN3MifQ",
  );
  expect(key2.keyType).toBe("Secp256k1");
  expect(key2.exportPublicKey()).toBe(
    "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  );
  expect(await Factory.toDIDJWK(key2)).toBe(
    "did:jwk:eyJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsInVzZSI6InNpZyIsImFsZyI6IkVTMjU2SyIsIngiOiJTUURPWnRJMERxQ0pmSERRb191NExCSmJvV1A1V1I3Z2tMNEplaEd0T2ZrIiwieSI6IkxIWUNOQlJTVDJHR2twY25PRHpvNGJQaW15TUVJd2U5cEsxUzVTc2poN3MifQ",
  );

  const key3 = await Factory.createFromDIDJWK(
    "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Inh1SjVMSnZnWTVhZ2VCVWJ5SjV2VlRRU3lyQUF4LXh4eGJtU2s0TlcyWUEiLCJ5IjoiWkh1allyLUhoTm1WcnRkZjRpY3p0Q00yZU1KNlhDcTQyTXd3dWhrRDZkRSJ9",
  );
  expect(key3.keyType).toBe("Secp256r1");
  expect(key3.exportPublicKey()).toBe(
    "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
  );
  expect(await Factory.toDIDJWK(key3)).toBe(
    "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoieHVKNUxKdmdZNWFnZUJVYnlKNXZWVFFTeXJBQXgteHh4Ym1TazROVzJZQSIsInkiOiJaSHVqWXItSGhObVZydGRmNGljenRDTTJlTUo2WENxNDJNd3d1aGtENmRFIn0",
  );
});

test("resolve", async () => {
  const key = await Factory.resolve(
    "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSDRvdHEzTnFTWUdkamJiNjZiWHNxZXFzeG1rTlhZZE8wOGJ6MGRQbHpjSSIsInkiOiJoeHRwVU5CUEp1WUg5ZVdldDh4X01pV0V3MUpPV0RVZU5OR0JVQ1VjbmFRIn0",
  );
  expect(key).toBeDefined();
  expect(key.keyType).toBe("Secp256r1");
  expect(key.exportPublicKey()).toBe(
    "021f8a2dab736a49819d8db6fae9b5eca9eaacc6690d5d874ed3c6f3d1d3e5cdc2",
  );
});

test("resolve did:key with jwk", async () => {
  const key = await Factory.resolve(
    "did:key:z2SpZdbv3LZ9yeUBaekRedETjR3HegR2VYYuS6JvVSXDbCB29vfrer3EwetJVYwJ7qBnMYfrepE16mrjBcug9AoQcf3vphsmF2qhTWRf3rFH5fJ7onG76cAaRzH8YSpUMrFJqLP1RUxudYfF5KENrF17ermCfGfdBYjtYsGTuoeYnGBRBJiJKtAx3uK5ADhCteUhaCW3EwW4ezqx98hmjxxPbTJ",
  );
  expect(key).toBeDefined();
  expect(key.keyType).toBe("Secp256k1");
  expect(key.exportPublicKey()).toBe(
    "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  );
});

test("instantiate ed25519 with 64bit private key", async () => {
  const privkeyhex =
    "b5f28b7cd658b8f050e7832024f0d15bd8a6868e3bb6cc06e1405e9b11308b4963b78f6b857df765a63e55ebbfb546e8d043ca6760b26f5c056883bd845d34c3";
  const key = await Factory.createFromType("Ed25519", privkeyhex);
  expect(key).toBeDefined();
  expect(key.keyType).toBe("Ed25519");
  expect(key.exportPublicKey()).toBe(
    "63b78f6b857df765a63e55ebbfb546e8d043ca6760b26f5c056883bd845d34c3",
  );
});

test("instantiate ed25519 with 64bit private key (2)", async () => {
  const privkeyhex =
    "6d8be598361a5ccae3400ab3ae172a105bc9ee0a3bad33e85e0257a1f5755b2778faa7e63fee80449bcb89e706c544f5f43849ddb2ffdc41f80316ae3ff2dc96";
  const key = await Factory.createFromType("Ed25519", privkeyhex);
  expect(key).toBeDefined();
  expect(key.keyType).toBe("Ed25519");
  expect(key.exportPublicKey()).toBe(
    "78faa7e63fee80449bcb89e706c544f5f43849ddb2ffdc41f80316ae3ff2dc96",
  );
});

test("get key reference", () => {
  expect(
    Factory.getKeyReference(
      "did:key:zQ3shjZ5btPjB5qhUqJyH68XczxL11JqCTng4XBwhdy9nVYic",
    ),
  ).toBe("zQ3shjZ5btPjB5qhUqJyH68XczxL11JqCTng4XBwhdy9nVYic");
  expect(Factory.getKeyReference("did:web:lala")).toBe("0");
  expect(Factory.getKeyReference("did:jwk:lala")).toBe("0");
});
