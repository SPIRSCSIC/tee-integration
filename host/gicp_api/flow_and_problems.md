# Flow (4G)

Following the governance scheme, a PoC has been created with the procedures required.
File `api/poc.py` contains multiple examples of how to use the API provided
by `api/server.py`:

## Server endpoints
- Anonymization Schemes:
  - **GET** /anonymization/schemes: Returns a list of available anonymization schemes.
  - **POST** /anonymization/schemes/\<scheme>: Handles the anonymization
    of a dataset using the specified scheme.

- Group Signature Management:
  - **GET** /groupsig/groups: Lists all available groups.
  - **POST** /groupsig/groups: Creates a new group for group signatures.
  - **POST** /groupsig/groups/\<group>: Registers a new member in a specified group.
  - **POST** /groupsig/groups/\<group>/sign: Signs a message using a group member’s key.
  - **POST** /groupsig/groups/\<group>/verify: Verifies a signature against a message in a specified group.

  These functions should be protected under access control:
  - **GET** /groupsig/groups/\<group>/open: Reveals the identity of the signer in a group signature.
  - **POST** /groupsig/groups/\<group>/revoke: Revokes a member's identity in a group.
  - **GET** /groupsig/groups/\<group>/revoked: Checks if an identity in a group has been revoked.

## PoC examples
There are 3 examples in `api/client.py`:
- mondrian: simple flow of the anonymization API using mondrian
- groupsig: simple flow of the groupsig API
- governance_scheme: definition of the flow represented in the governance
  scheme applied to 4G.
  > Note: Storing in DLT and Repository is skipped, we currently
  > use files in the PoC, however, this should be developed in a proper way.

# Problems
## Registration inside TEE
Currently, identity registration is done inside the TEE, that means
the group manager **knows** the _member key_ before sending it<sup>1</sup>.
Actually, this process should be divided in a multi-step
registration so the user generates the key in their last step. We are
currently addressing this dependency issue to enable this multi-step registration
process.

# Signing inside TEE
The signature is a process that should be done by the member locally, that means it must
obtain the group key and then sign it using specialized software.
Currently, the user must send their _member key_ to the server<sup>1</sup>. We are working
on this software to allow local signing.

<sup>1</sup> Which is not ideal even if it is sent using a secure channel
