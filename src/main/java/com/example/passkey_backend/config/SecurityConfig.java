package com.example.passkey_backend.config;


import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(withDefaults())
                .webAuthn(webAuthn -> webAuthn
                        .rpName("My Relying Party")
                        .rpId("localhost")
                        .allowedOrigins("https://localhost:8443")
                );
        return http.build();
    }
}
