package com.rolea.learning.oauthserver.security.enhancers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

/**
 * Sample fo accessing the access and refresh tokens
 * Note that you can override tokens here
 */
@Component
public class LogEnhancer implements OAuthTokenEnhancer{

    private static final Logger LOG = LoggerFactory.getLogger(LogEnhancer.class);
    private static final int ORDER = 2;

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        DefaultOAuth2AccessToken enhancedToken = (DefaultOAuth2AccessToken) accessToken;
        LOG.info("Access token {}", enhancedToken.getValue());
        LOG.info("Refresh token {}", enhancedToken.getRefreshToken().getValue());
        return accessToken;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

}
