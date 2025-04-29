import { test, expect } from 'vitest';
import { TKeyType } from '@veramo/core-types';
import { Ed25519 } from '../src/Ed25519';

test("Initialise key", () => {
    const key = new Ed25519();
    key.createPrivateKey();
    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.privateKeyBytes === null).toBeFalsy();
    expect(key.privateKeyBytes!.length).toBe(32);
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(32);

    expect(key.algorithms()).toContain('EdDSA');
});

test("import private key", () => {
    const key = new Ed25519();
    key.initialisePrivateKey(key.hexToBytes('fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8'));
    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.privateKeyBytes === null).toBeFalsy();
    expect(key.privateKeyBytes!.length).toBe(32);
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(32);
    expect(key.exportPrivateKey()).toBe('fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8');
    expect(key.exportPublicKey()).toBe('5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39');
});

test("create JWK", () => {
    const key = new Ed25519();
    key.initialisePrivateKey(key.hexToBytes('fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8'));
    expect(key.hasPrivateKey()).toBeTruthy();

    const jwk = key.toJWK();
    expect(!!jwk).toBeTruthy();
    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.x).toBe('XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk');
});

test("import from DID", () => {
    const key = new Ed25519();
    key.importFromDid('did:key:z6Mkkf9RiKeaAFaQzQGT2zfqqwCYYbPTNhQvyGXjKJ84kW88');
    expect(key.hasPrivateKey()).toBeFalsy();
    expect(key.privateKeyBytes === null).toBeTruthy();
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(32);
    expect(key.exportPublicKey()).toBe('5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39');
});


test("export to DID", () => {
    const key = new Ed25519();
    key.initialisePrivateKey(key.hexToBytes('fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8'));
    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.toDIDKey()).toBe('z6Mkkf9RiKeaAFaQzQGT2zfqqwCYYbPTNhQvyGXjKJ84kW88');
});

test("import from managed key", () => {
    const key = new Ed25519();
    const mkey = {
        kid: '5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39',
        type: 'Ed25519' as TKeyType,
        kms: 'default',
        publicKeyHex: '5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39',
        privateKeyHex: 'fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8'
    };
    key.importFromManagedKey(mkey);

    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.privateKeyBytes === null).toBeFalsy();
    expect(key.privateKeyBytes!.length).toBe(32);
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(32);
    expect(key.exportPrivateKey()).toBe('fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8');
    expect(key.exportPublicKey()).toBe('5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39');
});

test("import from managed public key", () => {
    const key = new Ed25519();
    const mkey = {
        kid: '5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39',
        type: 'Ed25519' as TKeyType,
        kms: 'default',
        publicKeyHex: '5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39'
    };
    key.importFromManagedKey(mkey);

    expect(key.hasPrivateKey()).toBeFalsy();
    expect(key.privateKeyBytes === null).toBeTruthy();
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(32);
    expect(key.exportPublicKey()).toBe('5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39');
});

test('signature', async () => {
    const key = new Ed25519();
    key.initialisePrivateKey(key.hexToBytes('fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8'));
    expect(key.hasPrivateKey()).toBeTruthy();
    const message = Buffer.from('Message Data', 'utf-8');
    const signature = await key.sign('EdDSA', message, 'base64url');
    expect(signature).toBe('9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg');

    const signature64 = await key.sign('EdDSA', message, 'base64');
    expect(signature64).toBe('9Ud+wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq+r6BEl5THBh8ze4/Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg');

    const signature16 = await key.sign('EdDSA', message, 'base16');
    expect(signature16).toBe('f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06');

    const signaturehex = await key.sign('EdDSA', message, 'hex');
    expect(signaturehex).toBe('f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06');
})

test('verify', async() => {
    const key = new Ed25519();
    key.initialisePrivateKey(key.hexToBytes('fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8'));
    expect(key.hasPrivateKey()).toBeTruthy();
    const message = Buffer.from('Message Data', 'utf-8');
    const signature = await key.sign('EdDSA', message, 'base64url');
    expect(key.verify('EdDSA', signature, message)).toBeTruthy();
});