# Opaque transport protocol

## Version

The current wire record version is `2`. Cryptographic derivation uses the stable internal namespace `angusu.bridge/opaque-envelope/v2`. Product branding is deliberately excluded from this namespace so a product rename does not invalidate existing ciphertext.

## Field envelope

Each mapped field is independently sealed using:

- ephemeral X25519 sender key
- destination X25519 public key
- HKDF-SHA256 derived field key
- random 96-bit ChaCha20-Poly1305 nonce
- ChaCha20-Poly1305 authenticated encryption

The authenticated context includes:

- tenant
- source connector ID
- destination connector ID
- field ID
- schema version
- record ID
- transfer ID
- mapping plan ID
- mapping plan digest
- protocol version
- optional issuance and expiration timestamps

Changing authenticated metadata without re-encrypting the field causes authentication failure at the destination.

## Record integrity

A `BlindTransportRecord` rejects:

- empty records
- duplicate destination fields
- field IDs that disagree with authenticated context
- mixed record, tenant, route, transfer, plan, schema or protocol metadata
- unsupported protocol versions
- ciphertext or wire records above configured limits

The canonical wire representation is JSON with deterministic key ordering and compact separators. Its SHA-256 digest is used by relay, ledger and spool identity checks. The digest is not a payload hash of plaintext.

## Confidentiality boundary

The protocol hides field payload values from a relay that receives only wire records and does not possess the destination private key. It does not hide routing metadata or field identifiers. It also does not protect plaintext from a compromised source or destination host.

## Expiration

A source agent may authenticate `issued_at` and `expires_at`. Destination decryption checks expiry. Relay policy can additionally require an expiry and reject lifetimes above its configured maximum.
