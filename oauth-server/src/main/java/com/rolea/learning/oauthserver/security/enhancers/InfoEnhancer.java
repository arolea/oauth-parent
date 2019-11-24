package com.rolea.learning.oauthserver.security.enhancers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sample of adding attributes to the /oauth/token endpoint response
 */
@Component
public class InfoEnhancer implements OAuthTokenEnhancer {

    private static final Logger LOG = LoggerFactory.getLogger(LogEnhancer.class);
    private static final int ORDER = 0;
    private static final String CREATION_TIMESTAMP = "created_at";

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        LOG.info("Appending additional information to response");
        DefaultOAuth2AccessToken enhancedToken = (DefaultOAuth2AccessToken) accessToken;
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put(CREATION_TIMESTAMP, System.currentTimeMillis());
        enhancedToken.setAdditionalInformation(metadata);
        return accessToken;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

}
