package com.rolea.learning.oauthserver.security.social.impl;

import com.rolea.learning.oauthserver.domain.UserAccount;
import com.rolea.learning.oauthserver.domain.UserRole;
import com.rolea.learning.oauthserver.persistence.UserAccountRepository;
import com.rolea.learning.oauthserver.security.core.OAuthUser;
import com.rolea.learning.oauthserver.security.social.TokenAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import static java.util.Collections.singletonList;

@Component
public class KeycloakAuthenticator implements TokenAuthenticator {

    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticator.class);
    private static final String SOCIAL_LOGIN_TYPE = "keycloak";

    @Value("${keycloak.user.info.endpoint}")
    private String userInfoEndpoint;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private UserAccountRepository repository;

    @Override
    public String getType() {
        return SOCIAL_LOGIN_TYPE;
    }

    /**
     * If you want to validate the id token instead of invoking the userinfo endpoint, public keys are available at
     * http://localhost:8180/auth/realms/master/protocol/openid-connect/certs
     */
    @Override
    public Authentication apply(String token) {
        LOG.info("Authenticating based on keycloak id token");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("access_token", token);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        KeycloakUserInfoResponse response = restTemplate
                .postForEntity(userInfoEndpoint, request, KeycloakUserInfoResponse.class).getBody();

        UserAccount principal = repository.findByEmail(response.getEmail())
                .orElseGet(() -> repository.save(UserAccount.builder()
                        .email(response.getEmail())
                        .keycloakId(response.getSub())
                        .enabled(Boolean.TRUE)
                        .userRoles(singletonList(UserRole.ROLE_USER))
                        .build()
                ));

        OAuthUser userDetails = new OAuthUser(principal);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}
