package com.rolea.learning.oauthserver.security.social.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.rolea.learning.oauthserver.domain.UserAccount;
import com.rolea.learning.oauthserver.domain.UserRole;
import com.rolea.learning.oauthserver.persistence.UserAccountRepository;
import com.rolea.learning.oauthserver.security.core.OAuthUser;
import com.rolea.learning.oauthserver.security.social.TokenAuthenticator;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.List;

import static java.util.Collections.singletonList;

/**
 * See requests.json for sample usage
 */
@Component
public class GoogleAuthenticator implements TokenAuthenticator {

	private static final String SOCIAL_LOGIN_TYPE = "google";

	@Autowired
	private UserAccountRepository repository;

	@Value("#{'${social.login.google.client-ids}'.split(',')}")
	private List<String> allowedApps;

	@Override
	public String getType() {
		return SOCIAL_LOGIN_TYPE;
	}

	@Override
	@SneakyThrows
	public Authentication apply(String token) {
		// validate JWK
		GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport.Builder().build(), JacksonFactory.getDefaultInstance())
				.setAudience(allowedApps)
				.build();
		GoogleIdToken idToken = verifier.verify(token);

		// extract token body
		GoogleIdToken.Payload payload = idToken.getPayload();
		// create user account in case it does not already exist
		UserAccount principal = repository.findByEmail(payload.getEmail())
				.orElseGet(() -> repository.save(UserAccount.builder()
						.email(payload.getEmail())
						.googleId(payload.getSubject())
						.enabled(Boolean.TRUE)
						.userRoles(singletonList(UserRole.ROLE_USER))
						.build()
				));

		// return authentication
		OAuthUser userDetails = new OAuthUser(principal);
		return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
	}

}
