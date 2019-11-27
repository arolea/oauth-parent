package com.rolea.learning.oauthserver.security.enhancers;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum EnhancerName {

	INFO_ENHANCER("info_enhancer"),
	JWT_ENHANCER("jwt_enhancer"),
	LOG_ENHANCER("log_enhancer");

	String name;

}
