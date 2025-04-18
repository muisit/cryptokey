import { test, expect } from 'vitest';
import { TKeyType } from '@veramo/core-types';
import { Secp256r1 } from '../src/Secp256r1';

test("Initialise key", () => {
    const key = new Secp256r1();
    key.createPrivateKey();
    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.privateKeyBytes === null).toBeFalsy();
    expect(key.privateKeyBytes!.length).toBe(32);
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(33);

    expect(key.algorithms()).toContain('ES256');
});

test("import private key", () => {
    const key = new Secp256r1();
    key.initialisePrivateKey(key.hexToBytes('44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11'));
    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.privateKeyBytes === null).toBeFalsy();
    expect(key.privateKeyBytes!.length).toBe(32);
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(33);
    expect(key.exportPrivateKey()).toBe('44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11');
    expect(key.exportPublicKey()).toBe('03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980');
});

test("create JWK", () => {
    const key = new Secp256r1();
    key.initialisePrivateKey(key.hexToBytes('44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11'));
    expect(key.hasPrivateKey()).toBeTruthy();

    const jwk = key.toJWK();
    expect(!!jwk).toBeTruthy();
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.x).toBe('xuJ5LJvgY5ageBUbyJ5vVTQSyrAAx-xxxbmSk4NW2YA');
});

test("import from DID", () => {
    const key = new Secp256r1();
    key.importFromDid('did:key:zDnaew3eSC3JmvrFcgwgoGULgcm3iQR9han5k2d4P87vsDkdm');
    expect(key.hasPrivateKey()).toBeFalsy();
    expect(key.privateKeyBytes === null).toBeTruthy();
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(33);
    expect(key.exportPublicKey()).toBe('03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980');
});


test("export to DID", () => {
    const key = new Secp256r1();
    key.initialisePrivateKey(key.hexToBytes('44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11'));
    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.toDIDKey()).toBe('zDnaew3eSC3JmvrFcgwgoGULgcm3iQR9han5k2d4P87vsDkdm');
});

test("import from managed key", () => {
    const key = new Secp256r1();
    const mkey = {
        kid: '03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980',
        type: 'Ed25519' as TKeyType,
        kms: 'default',
        publicKeyHex: '03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980',
        privateKeyHex: '44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11'
    };
    key.importFromManagedKey(mkey);

    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.privateKeyBytes === null).toBeFalsy();
    expect(key.privateKeyBytes!.length).toBe(32);
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(33);
    expect(key.exportPrivateKey()).toBe('44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11');
    expect(key.exportPublicKey()).toBe('03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980');
});

test("import from managed public key", () => {
    const key = new Secp256r1();
    const mkey = {
        kid: '03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980',
        type: 'Secp256r1' as TKeyType,
        kms: 'default',
        publicKeyHex: '03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980'
    };
    key.importFromManagedKey(mkey);

    expect(key.hasPrivateKey()).toBeFalsy();
    expect(key.privateKeyBytes === null).toBeTruthy();
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(33);
    expect(key.exportPublicKey()).toBe('03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980');
});

test('signature', async () => {
    const key = new Secp256r1();
    key.initialisePrivateKey(key.hexToBytes('44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11'));
    expect(key.hasPrivateKey()).toBeTruthy();
    const message = Buffer.from('Message Data', 'utf-8');
    const signature = await key.sign('ES256', message, 'base64url');
    expect(signature).toBe('RRFwdKcuhC3-q2SG2laZKzB0VnSvyKQxqQAv3EDvPY0IhLrSO-33IVozCMKFT8toGQsL3NI-7d8t7Pp_xdbrqQ');

    const signature64 = await key.sign('ES256', message, 'base64');
    expect(signature64).toBe('RRFwdKcuhC3+q2SG2laZKzB0VnSvyKQxqQAv3EDvPY0IhLrSO+33IVozCMKFT8toGQsL3NI+7d8t7Pp/xdbrqQ');

    const signature16 = await key.sign('ES256', message, 'base16');
    expect(signature16).toBe('45117074a72e842dfeab6486da56992b30745674afc8a431a9002fdc40ef3d8d0884bad23bedf7215a3308c2854fcb68190b0bdcd23eeddf2decfa7fc5d6eba9');

    const signaturehex = await key.sign('ES256', message, 'hex');
    expect(signaturehex).toBe('45117074a72e842dfeab6486da56992b30745674afc8a431a9002fdc40ef3d8d0884bad23bedf7215a3308c2854fcb68190b0bdcd23eeddf2decfa7fc5d6eba9');
})