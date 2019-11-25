package com.rolea.learning.oauthserver.security.enhancers;

import org.springframework.security.oauth2.provider.token.TokenEnhancer;

/**
 * Adds ordering for token enhancers so you can control the order in which they are applied
 */
public interface OAuthTokenEnhancer extends TokenEnhancer {

    int getOrder();

}
