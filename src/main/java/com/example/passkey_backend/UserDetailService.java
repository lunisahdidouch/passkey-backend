package com.example.passkey_backend;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

public class UserDetailService {
    @Bean
    UserDetailsService users() {
        UserDetails u = User.withDefaultPasswordEncoder()
                .username("lunis")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(u);
    }

}
