# cryptokey

Cryptography implementation for assymetric keys in Node

## Key types

This library implements some methods for the following key types:

- Ed25519
- X25519
- P-256, prime256v1, Secp256r1
- Secp256k1

## Key Methods

### Basic methods

- `createPrivateKey`: initialises the private key to a random value
- `initialisePrivateKey(Uint8Array)`: initialise the private key to a set byte array
- `bytesToHex(Uint8Array)`: returns a `base16`/`hex` encoded string of the byte array
- `hexToBytes(string)`: returns a byte array based on the passed hexadecimal string
- `hasPublicKey()`: returns a boolean depending on the value of the public key byte array
- `publicKey()`: returns a byte array, empty if no public key is set
- `exportPublicKey()`: exports the public key in `hex` format
- `setPublicKey(string)`: sets the public key based on the hexadecimal string value
- `hasPrivateKey()`: returns a boolean depending on the value of the private key byte array
- `privateKey()`: returns a byte array, empty if no private key is set
- `exportPrivateKey()`: exports the private key in `hex` format
- `setPrivateKey(string)`: sets the private key based on the hexadecimal string value

## Other

- `toDIDKey()`: exports the key as a `did:key:..` identifier
- `importFromDID(string)`: imports a `did` identifier. Currently on `did:key:` is supported
- `toJWK()`: exports a JWK object for the public key
- `algorithms()`: provides a list of signature algorithms implemented
- `didDocument()`: returns the DID document value
- `importFromManagedKey(IKey)`: imports the key from a `@veramo/core` `IKey` structure
- `sign(string, Uint8Array, string)`: signs the byte array according to the algorithm (first parameter) and encodes the result according to the last parameter. Uses `raw` encoding by default, but `base64url` is an often used encoding
- `verify(string, string, Uint8Array)`: verifies the byte array agains the signature (second parameter) using the algorithm (first parameter)
