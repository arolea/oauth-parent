package com.rolea.learning.oauthserver.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
@EnableResourceServer
public class ResourceServer extends ResourceServerConfigurerAdapter {

    // If the ResourceServer would be deployed separately from the AuthorizationServer
    // We would have to redefine the TokenStore and the JWTAccessConverter here as well
    // See https://www.baeldung.com/spring-security-oauth-jwt for an example
    @Override
    public void configure(HttpSecurity http) throws Exception {
        // The default error message for unauthenticated requests can be customized via authenticationEntryPoint
        http.authorizeRequests()
                .anyRequest()
                .authenticated();
    }

}

