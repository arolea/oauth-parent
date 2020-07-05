package com.rolea.learning.oauthserver.security.social.impl;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class KeycloakUserInfoResponse {

    private String sub;
    private String name;
    private String email;

}
