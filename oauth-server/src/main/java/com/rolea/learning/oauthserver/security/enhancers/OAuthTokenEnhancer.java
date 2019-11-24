package com.rolea.learning.oauthserver.security.enhancers;

import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public interface OAuthTokenEnhancer extends TokenEnhancer {

    int getOrder();

}
