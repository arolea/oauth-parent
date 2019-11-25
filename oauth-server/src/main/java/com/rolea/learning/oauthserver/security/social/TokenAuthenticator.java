package com.rolea.learning.oauthserver.security.social;

import org.springframework.security.core.Authentication;

/**
 * Implemented by social authenticators
 */
public interface TokenAuthenticator {

    String getType();

    Authentication apply(String token);

}
