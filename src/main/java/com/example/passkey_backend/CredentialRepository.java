package com.example.passkey_backend;

import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.ByteArray;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface CredentialRepository {
    List<ByteArray> getCredentialIdsForUsername(String username);
    Optional<RegisteredCredential> lookup(ByteArray credentialId, String rpId);
    void saveCredential(String username, RegisteredCredential credential);
}