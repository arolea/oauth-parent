package com.rolea.learning.oauthserver.security.social;

import org.springframework.security.core.Authentication;

public interface TokenAuthenticator {

    String getType();

    Authentication apply(String token);

}
