package com.rolea.learning.oauthserver.security.core;

import com.rolea.learning.oauthserver.persistence.UserAccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class OAuthUserService implements UserDetailsService {

    @Autowired
    private UserAccountRepository repository;

    @Override
    public UserDetails loadUserByUsername(String email) {
        return repository.findByEmail(email)
                .map(OAuthUser::new)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

}