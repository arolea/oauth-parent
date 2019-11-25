package com.rolea.learning.oauthserver.security.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Used by ResourceOwnerPasswordTokenGranter for credentials check
 */
@Component
public class OAuthAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthAuthenticationProvider.class);

    private static final String GRANT_TYPE_KEY = "grant_type";
    private static final String GRANT_TYPE_PASSWORD_VALUE = "password";

    private static final String PARAM_USERNAME = "username";

    @Autowired
    private OAuthUserService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) {
        LOGGER.info("Authentication request {}", authentication);
        Map<String, String> details = (Map<String, String>) authentication.getDetails();

        if (!GRANT_TYPE_PASSWORD_VALUE.equals(details.get(GRANT_TYPE_KEY))) {
            return authentication;
        }

        String username = details.get(PARAM_USERNAME);
        String password = (String) authentication.getCredentials();
        if (username == null || password == null) {
            return authentication;
        }

        OAuthUser userDetails = (OAuthUser) userDetailsService.loadUserByUsername(username);
        if(userDetails == null){
            return authentication;
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            return authentication;
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
