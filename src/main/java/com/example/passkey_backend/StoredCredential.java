package com.example.passkey_backend;

import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.data.extension.client.ClientExtensionOutput;


import java.util.Objects;
import java.util.Set;

public abstract class StoredCredential implements CredentialRecord {

}