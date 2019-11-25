package com.rolea.learning.oauthserver.security.enhancers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * Sample of converting from plain tokens to JWT
 * Note that this is part of the enhancer chain has to be injected into the TokenStore as well
 */
@Component
@Primary
public class JWTEnhancer extends JwtAccessTokenConverter implements OAuthTokenEnhancer {

    private static final Logger LOG = LoggerFactory.getLogger(LogEnhancer.class);
    private static final int ORDER = 1;

    @Autowired
    private UserDetailsService userDetailsService;

    @Value("${jwt.signing.key}")
    private String signingKey;

    @PostConstruct
    public void init() {
        // Required so a Principal object is created based on JWT token and injected into the security context
        DefaultAccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();
        DefaultUserAuthenticationConverter authenticationConverter = new DefaultUserAuthenticationConverter();
        authenticationConverter.setUserDetailsService(userDetailsService);
        tokenConverter.setUserTokenConverter(authenticationConverter);
        // Using a signing key assumes the signing key is available on the ResourceServer as well
        // If this is not possible, use a key pair instead and share the public key with the ResourceServer
        this.setSigningKey(signingKey);
        this.setAccessTokenConverter(tokenConverter);
    }

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        LOG.info("Converting tokens to JWT");
        return super.enhance(accessToken, authentication);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

}

