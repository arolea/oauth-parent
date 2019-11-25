package com.rolea.learning.oauthserver.security;

import com.rolea.learning.oauthserver.security.enhancers.JWTEnhancer;
import com.rolea.learning.oauthserver.security.enhancers.OAuthTokenEnhancer;
import com.rolea.learning.oauthserver.security.social.SocialTokenGranter;
import com.rolea.learning.oauthserver.security.social.TokenAuthenticator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.List;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static java.util.Comparator.comparing;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    private static final String CLIENT_ID = "test";
    private static final String CLIENT_SECRET = "test";
    private static final String[] GRANT_TYPES = {"refresh_token", "password", "social"};
    private static final String[] SCOPES = {"read", "write"};

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private List<OAuthTokenEnhancer> enhancers;

    @Autowired
	private List<TokenAuthenticator> socialAuthenticators;

    @Autowired
    private JWTEnhancer jwtAccessTokenConverter;

    @Value("${access.token.expire}")
    private Integer accessTokenLifespan;

    @Value("${refresh.token.expire}")
    private Integer refreshTokenLifespan;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient(CLIENT_ID)
                .secret(passwordEncoder.encode(CLIENT_SECRET))
                .authorizedGrantTypes(GRANT_TYPES)
                .scopes(SCOPES)
                .autoApprove(true)
                .accessTokenValiditySeconds(accessTokenLifespan)
                .refreshTokenValiditySeconds(refreshTokenLifespan);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        List<TokenEnhancer> tokenEnhancers = enhancers
                .stream()
                .sorted(comparing(OAuthTokenEnhancer::getOrder))
                .collect(Collectors.toList());

        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(tokenEnhancers);

		TokenGranter tokenGranter = endpoints.getTokenGranter();
		TokenGranter compositeTokenGranter = new CompositeTokenGranter(asList(
				tokenGranter,
				new SocialTokenGranter(
						socialAuthenticators,
						endpoints.getTokenServices(),
						endpoints.getClientDetailsService(),
						endpoints.getOAuth2RequestFactory()
				)
		));

        endpoints
                .tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain)
				.tokenGranter(compositeTokenGranter)
                .accessTokenConverter(jwtAccessTokenConverter)
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false);
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter);
    }

}

