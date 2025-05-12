package com.example.passkey_backend;

import org.springframework.stereotype.Component;

@Component
public abstract class InMemoryCredentialRepository implements CredentialRepository  {
    // internally keep maps of user → credential IDs, public keys, counters, etc.
    // implement methods:
    //   List<ByteArray> getCredentialIdsForUsername(String username);
    //   Optional<RegisteredCredential> lookup(ByteArray credentialId, String rpId, UserVerificationRequirement);
    //   void saveCredential(String username, RegisteredCredential credential);
}
