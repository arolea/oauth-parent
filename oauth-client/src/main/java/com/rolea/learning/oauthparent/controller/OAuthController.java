package com.rolea.learning.oauthparent.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
public class OAuthController {

	private static final ObjectMapper MAPPER = new ObjectMapper();
	private static final RestTemplate REST_TEMPLATE = new RestTemplate();

	@GetMapping("/")
	public Object getTokenData(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) throws JsonProcessingException {
		Map<String, Object> data = new HashMap<>();
		data.put("authorizedClient", MAPPER.writeValueAsString(authorizedClient));
		data.put("userInfo", getUserInfo(authorizedClient));
		return data;
	}

	private Map<String, String> getUserInfo(OAuth2AuthorizedClient authorizedClient){
		String userInfoEndpointUri = authorizedClient
				.getClientRegistration()
				.getProviderDetails()
				.getUserInfoEndpoint()
				.getUri();

		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue());
		return REST_TEMPLATE.exchange(
				userInfoEndpointUri,
				HttpMethod.GET,
				new HttpEntity<>(headers),
				new ParameterizedTypeReference<Map<String, String>>() {}
				).getBody();
	}

}
