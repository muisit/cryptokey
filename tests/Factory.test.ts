import { test, expect } from "vitest";
import { Factory } from "../src/Factory";

test("create from did", () => {
  let key1 = Factory.createFromDidKey(
    "did:key:z6Mkkf9RiKeaAFaQzQGT2zfqqwCYYbPTNhQvyGXjKJ84kW88",
  );
  expect(key1.keyType).toBe("Ed25519");
  expect(key1.exportPublicKey()).toBe(
    "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
  );

  let key2 = Factory.createFromDidKey(
    "did:key:zQ3shjZ5btPjB5qhUqJyH68XczxL11JqCTng4XBwhdy9nVYic",
  );
  expect(key2.keyType).toBe("Secp256k1");
  expect(key2.exportPublicKey()).toBe(
    "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  );

  let key3 = Factory.createFromDidKey(
    "did:key:zDnaew3eSC3JmvrFcgwgoGULgcm3iQR9han5k2d4P87vsDkdm",
  );
  expect(key3.keyType).toBe("Secp256r1");
  expect(key3.exportPublicKey()).toBe(
    "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
  );
});

test("create from jwk", () => {
  let key1 = Factory.createFromJWK({
    kty: "OKP",
    crv: "Ed25519",
    x: "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
  });
  expect(key1.keyType).toBe("Ed25519");
  expect(key1.exportPublicKey()).toBe(
    "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
  );

  let key2 = Factory.createFromJWK({
    kty: "EC",
    crv: "secp256k1",
    x: "SQDOZtI0DqCJfHDQo_u4LBJboWP5WR7gkL4JehGtOfk",
    y: "LHYCNBRST2GGkpcnODzo4bPimyMEIwe9pK1S5Ssjh7s",
  });
  expect(key2.keyType).toBe("Secp256k1");
  expect(key2.exportPublicKey()).toBe(
    "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  );

  let key3 = Factory.createFromJWK({
    kty: "EC",
    crv: "P-256",
    x: "xuJ5LJvgY5ageBUbyJ5vVTQSyrAAx-xxxbmSk4NW2YA",
    y: "ZHujYr-HhNmVrtdf4icztCM2eMJ6XCq42MwwuhkD6dE",
  });
  expect(key3.keyType).toBe("Secp256r1");
  expect(key3.exportPublicKey()).toBe(
    "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
  );
});

test("create from managed key", () => {
  let key1 = Factory.createFromManagedKey({
    kid: "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
    type: "Ed25519",
    kms: "default",
    publicKeyHex:
      "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
  });
  expect(key1.keyType).toBe("Ed25519");
  expect(key1.exportPublicKey()).toBe(
    "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39",
  );

  let key2 = Factory.createFromManagedKey({
    kid: "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
    type: "Secp256k1",
    kms: "default",
    publicKeyHex:
      "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  });
  expect(key2.keyType).toBe("Secp256k1");
  expect(key2.exportPublicKey()).toBe(
    "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9",
  );

  let key3 = Factory.createFromManagedKey({
    kid: "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
    type: "Secp256r1",
    kms: "default",
    publicKeyHex:
      "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
  });
  expect(key3.keyType).toBe("Secp256r1");
  expect(key3.exportPublicKey()).toBe(
    "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980",
  );
});
