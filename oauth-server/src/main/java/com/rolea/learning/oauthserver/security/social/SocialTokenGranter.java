package com.rolea.learning.oauthserver.security.social;

import com.rolea.learning.oauthserver.security.social.impl.GoogleAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.util.stream.Collectors.toMap;

/**
 * Adds support for the social custom grant type
 */
public class SocialTokenGranter extends AbstractTokenGranter {

    private static final Logger LOG = LoggerFactory.getLogger(SocialTokenGranter.class);
    private static final String GRANT_TYPE = "social";

    private Map<String, TokenAuthenticator> adaptersMap;

    public SocialTokenGranter(
            List<TokenAuthenticator> adapters,
            AuthorizationServerTokenServices tokenServices,
            ClientDetailsService clientDetailsService,
            OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.adaptersMap = adapters.stream()
                .collect(toMap(TokenAuthenticator::getType, Function.identity()));
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        LOG.info("Starting social authentication flow");

        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());
        String type = parameters.get("type");
        String token = parameters.get("token");

        if(adaptersMap.containsKey(type)){
            Authentication userAuth = adaptersMap.get(type).apply(token);
            OAuth2Request storedOAuth2Request = this.getRequestFactory().createOAuth2Request(client, tokenRequest);
            return new OAuth2Authentication(storedOAuth2Request, userAuth);
        } else {
            throw new RuntimeException("Could not authenticate user");
        }
    }

}
