package com.sogeti.passkey_backend_yubico;


//import com.sogeti.passkey_backend_yubico.InMemoryCredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
public class WebAuthnConfig {

    @Bean
    public RelyingParty relyingParty(InMemoryCredentialRepository credentialRepository) {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id("localhost")
                .name("Passkey backend using the java-webauthn-server library")
                .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(credentialRepository)
                //Setting up the trusted source for only the necessary ports.
                .origins(Set.of("http://localhost:8080")) // Add port for the frontend that I will still create.
                .build();
    }
}