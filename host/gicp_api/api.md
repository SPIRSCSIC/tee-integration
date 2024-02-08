## Groupsig
### Setup
Generates and initializes the group and manager keys for any arbitrary group
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- Out: crypto [str] JSON filled with the bytes of the grpkey, mgrkey, gml and crl

### add_member
Adds new member to the group
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- Out: memkey [bytes] Member key

### sign
Issues a group signature
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: memkey [bytes] Member key
- In: msg [str] Message
- Out: signature [bytes] Signature

### verify_signature
Verifies a group signature
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: msg Text to be verified
- In: signature [bytes] Signature
- Out: rc [int] 1 if correct, 0 otherwise

### claim
Claims ownership of a group signature
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: memkey [bytes] Member key
- In: signature [bytes] Signature
- Out: proof [bytes] Claim proof

### claim_verify
Verifies a claim of a group signature
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: signature [bytes] Signature
- In: proof [bytes] Claim proof
- Out: rc [int] 1 if correct, 0 otherwise

### prove_equality
Generalization of the claiming process. Claims ownership of a set of
group signatures
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: memkey [bytes] Member key
- In: signatures [list[bytes]] Signatures
- Out: proof [bytes] Claim proof

### prove_equality_verify
Generalization of the claim verification process. Verifies a claim of a set of
group signatures
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: signatures [list[bytes]] Signatures
- In: proof [bytes] Claim proof
- Out: rc [int] 1 if correct, 0 otherwise

### open
Extracts the identity of the issuer of a specific group signature.
May generate a proof of opening.
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: mgrkey [bytes] Manager key
- In: gml [bytes] Group Membership List
- In: crl [bytes] Certificate Revocation List
- In: signature [bytes] Signature
- Out: idx [int] index of the issuer in the gml
- Out: proof [bytes, optional] Proof of opening

### reveal
Extracts the tracing trapdoor of a group member and adds member to CRL.
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: gml [bytes] Group Membership List
- In: crl [bytes] Certificate Revocation List
- In: idx [int] index of the issuer in the gml
- Out: rc [int] 1 if correct, 0 otherwise

### trace
Checks whether a group signature has been issued by a group member
who has been somehow revoked
- In: schema [int] Schema to be used: 0 kty04, 1 ps16
- In: grpkey [bytes] Group key
- In: mgrkey [bytes] Manager key
- In: gml [bytes] Group Membership List
- In: crl [bytes] Certificate Revocation List
- In: signature [bytes] Signature
- Out: rc [int] 1 if correct, 0 otherwise

## Anonimization
### Mondrian
Anonymizes a given dataset
- In: input [str] Dataset to be anonymized
- In: k [int, optional] k-Anonymity. Defaults to 10
- In: anonymize [flag, optional] Anonymizes output
- In: relaxed [flag, optional] Uses relaxed mode instead of strict
- Out: output [str] Processed dataset
