import { test, expect } from "vitest";
import { RSA } from "../src/RSA";
import { Factory } from "../src/Factory";
import { TKeyType } from "@veramo/core-types";

const privkeyhex =
  "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100e549e4baec81e250bad45fb9fe609d9a34b697ae081192c56c9381dd598614f1e5eb0be8dc04db809fec942c771c91c1d2cd7da7d83f801df61039662c538c465b68ddca46d982f7ca6bbff57054b6ae1e66caf5eb9bc6225b4ae6781b00a9bbfd3eb90cbbfa07969972316e9a4db992eae688d2f0f04f81c6649e9d13f9aa75c23159f325fd64f882b74d00d8d0558cdba08a930188c71592cbe2df9017a9c20e6dd6fd11ef62549434149ce596bd299e8de188365e3c0166a72d7ed8e3949a14258cd5276096aed90c2e362d8eb010ae4301be9d5440af22a80e954032817a57db8b5ea897fe0b4da92a8bac4567a90c13caf5afd2fa6e403bf23539dc372d020301000102820100095b54054918537664c01212fa92e7438f21f76674f255f96400fb544a2e60504472c1d194199cfa8401891a17c1ecf474fd894298f41dc3e5e77616d9b96418a29626323664c86fd90d14c58ce5616f66bd5e4c1da6b04b1fcb6fef17f7aae0341eae8f058f17bc592686e6b84f1d2da613d7cd61e3309f6a0b9a49c1dd01a173a519bf9c74175fbb98bb486544988cfcf5860ca93a11ecd28bb8571a87917e7c91d3428abad44a33903ded6571d397211442c037db43efe9d4122de78036036d2097b2b4809fb2718d7cda36ce5c6ae8b46fa13cb242cfa20899323298e68ada6bff99f75eb77c82241082dd9c161c311fff2dadbc9efcc9e7d868b5daf61102818100f42eeea9deea5902cbb3c248389be8fe346fbd63c123913c6dba5d44a478456351b0cb0383f4bf0a30942ed7d373a729ac47d19a31faf25ef09d73c244c8873b9a417fcae81b17e43a49e8050d32f5799abbf30f745806e21812b13952ff35334ce149d6fb53848539fdddb4cff47f8975b747e2ddbfb3b31130ebefdf04fb9102818100f062703215ed017ec05fc1e899fbd26bcf358e0bdd264c70dddd0165f77fe5b78567c45905aae653275d7bc2b8d2bf80e01ae45abb1b3ca1991d118e47a0fd56a53816646bfd6bed86d7ce0282baadefded6edd9dc56116689c482767c371f16a6a4b5d9efbea53b298efbdd868fd6b71bc16df957c107a0934a753b28badbdd028181008387fc5b588e57a01fe616931c9b2f282f4ab973d087be2614dd3c7c4b33d5fca7f65984ed419ade7c4875eb2025be37be6b79465c01d728b8e7b7813fd7dcb088691bd34aafbd70dccd0ec419d6075097bf0230a2f4ffd02e33736f737bb1468ef513f74fae2f462c74c9462a768374a20a3618c86609003e146222f5b9136102818038eef7a7c52da72700252de60b626b4a017fabaeffa7ec7ee6ed4b417d471b7f45e777c7a5e1fe3f3f99929061f9f8456bceb2bb1289b6e8873d2d45478dc7b2d7dadae2d9f8e1b11638d2a0219a594bf0b9730820797a11911babd2a844dde61d7df15c36be2ea03e8d90f5bcc32095a9cb3c62cbf7f9f87c2a2c6de08db1390281806b1146b2b72b1c4bed667cb1b039461ab5095451121bf49f7ee12bb994c7bfca3cbdd24ca8b15f3b207f9391dba589a49ebaa988a6d10a3dafb03441e543df52a6439b8843ecdfc6257fd95e7a35dede7cd1744066bf320ed2651a292518198eea21f51660d30d8d1e7467c20548f6e7913f37bd8f417bb26d8cb69058648179";
const pubkeyhex =
  "30820122300d06092a864886f70d01010105000382010f003082010a0282010100e549e4baec81e250bad45fb9fe609d9a34b697ae081192c56c9381dd598614f1e5eb0be8dc04db809fec942c771c91c1d2cd7da7d83f801df61039662c538c465b68ddca46d982f7ca6bbff57054b6ae1e66caf5eb9bc6225b4ae6781b00a9bbfd3eb90cbbfa07969972316e9a4db992eae688d2f0f04f81c6649e9d13f9aa75c23159f325fd64f882b74d00d8d0558cdba08a930188c71592cbe2df9017a9c20e6dd6fd11ef62549434149ce596bd299e8de188365e3c0166a72d7ed8e3949a14258cd5276096aed90c2e362d8eb010ae4301be9d5440af22a80e954032817a57db8b5ea897fe0b4da92a8bac4567a90c13caf5afd2fa6e403bf23539dc372d0203010001";

test("Initialise key", async () => {
  const key = new RSA();
  await key.createPrivateKey();
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(1216);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);

  expect(key.algorithms()).toContain("RS256");
});

test("import private key", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(1216);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);
  expect(key.exportPrivateKey()).toBe(privkeyhex);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from DID", async () => {
  const key = await Factory.createFromDIDKey(
    "did:key:z2MGw4gk84USotaWf4AkJ83DcnrfgGaceF86KQXRYMfQ7xqnUGCh4Hdof93yJSQEDGruanJWynvWoKKXAogAmrZR8e86gGt4HNbiaZTc5zSYjdJb5DLFtS2MozrRo1cfju4MiTgrauzYFnJGenGWv8oPN1Tvznrsx2zz6oiAqxxEq3Y3G2RRvihFSywxJ4vveJfDnj5w7ob4mkmqikTbATwTcaqX858mjbHFd4evKJNsME1sG4nheGXHWhXovfmw7GMCibPHtYZ8vJWzFUjbZagmT8XDaJApTt6sxWidWX6DWwgjAETvLkwuhv3D8YDcCgYS13fULsdcy63mweSCvQUhvFqHhfTfsMUmhZYZR1mUqMeBmHtj5EJd47u8ay8x2iSZBUgwxfFsJK7RsSoaBS",
  );
  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("export to DID", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(await Factory.toDIDKey(key)).toBe(
    "did:key:z2MGw4gk84USotaWf4AkJ83DcnrfgGaceF86KQXRYMfQ7xqnUGCh4Hdof93yJSQEDGruanJWynvWoKKXAogAmrZR8e86gGt4HNbiaZTc5zSYjdJb5DLFtS2MozrRo1cfju4MiTgrauzYFnJGenGWv8oPN1Tvznrsx2zz6oiAqxxEq3Y3G2RRvihFSywxJ4vveJfDnj5w7ob4mkmqikTbATwTcaqX858mjbHFd4evKJNsME1sG4nheGXHWhXovfmw7GMCibPHtYZ8vJWzFUjbZagmT8XDaJApTt6sxWidWX6DWwgjAETvLkwuhv3D8YDcCgYS13fULsdcy63mweSCvQUhvFqHhfTfsMUmhZYZR1mUqMeBmHtj5EJd47u8ay8x2iSZBUgwxfFsJK7RsSoaBS",
  );
});

test("import from managed key", async () => {
  const key = new RSA();
  const mkey = {
    kid: pubkeyhex,
    type: "RSA" as TKeyType,
    kms: "default",
    publicKeyHex: pubkeyhex,
    privateKeyHex: privkeyhex,
  };
  await key.importFromManagedKey(mkey);

  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPrivateKey()).toBe(privkeyhex);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from managed public key", async () => {
  const key = new RSA();
  const mkey = {
    kid: pubkeyhex,
    type: "RSA" as TKeyType,
    kms: "default",
    publicKeyHex: pubkeyhex,
  };
  await key.importFromManagedKey(mkey);

  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("signature RSA256", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS256", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature64 = await key.sign("RS256", message, "base64");
  expect(signature64).toBe(
    "9Ud+wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq+r6BEl5THBh8ze4/Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature16 = await key.sign("RS256", message, "base16");
  expect(signature16).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );

  const signaturehex = await key.sign("RS256", message, "hex");
  expect(signaturehex).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );
});

test("signature RSA512", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS512", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature64 = await key.sign("RS512", message, "base64");
  expect(signature64).toBe(
    "9Ud+wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq+r6BEl5THBh8ze4/Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature16 = await key.sign("RS512", message, "base16");
  expect(signature16).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );

  const signaturehex = await key.sign("RS512", message, "hex");
  expect(signaturehex).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );
});

test("verify", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS256", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );
  const sigbytes = key.base64UrlToBytes(signature);
  expect(sigbytes.length).toBe(64);
  expect(await key.verify("RS256", sigbytes, message)).toBeTruthy();
});

test("create JWK", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();

  const jwk = await key.toJWK();
  expect(!!jwk).toBeTruthy();
  expect(jwk.kty).toBe("RSA");
  expect(jwk.n).toBe("XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk");
  expect(jwk.e).toBe("XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk");
});

test("import JWK", async () => {
  const jwk = {
    kty: "RSA",
    n: "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
    e: "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
  };
  const key = new RSA();
  await key.importFromJWK(jwk);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});
