package com.rolea.learning.oauthserver.controller;

import com.rolea.learning.oauthserver.security.core.OAuthUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller used to demo permissions mappings for the authenticated principal
 */
@RestController
public class SampleController {

    private static final Logger LOG = LoggerFactory.getLogger(SampleController.class);

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping(value = "/user")
    public String helloUser(@AuthenticationPrincipal OAuthUser principal){
        LOG.info("Principal: {}", principal);
        return "Hello user";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping(value = "/admin")
    public String helloAdmin(@AuthenticationPrincipal OAuthUser principal) {
        LOG.info("Principal: {}", principal);
        return "Hello admin";
    }

}
