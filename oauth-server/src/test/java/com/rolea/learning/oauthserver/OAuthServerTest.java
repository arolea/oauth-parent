package com.rolea.learning.oauthserver;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class OAuthServerTest {

    @Autowired
    private TestRestTemplate template;

    @Test
    public void userLogin_ok(){
        ResponseEntity<Map<String, String>> response = login("alexrolea1@gmail.com", "password");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("access_token")).isNotNull();
        assertThat(response.getBody().get("refresh_token")).isNotNull();
    }

    @Test
    public void userLogin_unauthorized(){
        ResponseEntity<Map<String, String>> response = login("alexrolea2@gmail.com", "password");

        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.OK);
    }

    @Test
    public void adminLogin_ok(){
        ResponseEntity<Map<String, String>> response = login("alexrolea93@gmail.com", "password");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("access_token")).isNotNull();
        assertThat(response.getBody().get("refresh_token")).isNotNull();
    }

    @Test
    public void consumerUserEndpoint_ok(){
        ResponseEntity<Map<String, String>> loginResponse = login("alexrolea1@gmail.com", "password");
        String accessToken = loginResponse.getBody().get("access_token");

        ResponseEntity<String> response = consumeEndpoint("/user", accessToken);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void consumerUserEndpoint_unauthorized(){
        ResponseEntity<Map<String, String>> loginResponse = login("alexrolea1@gmail.com", "password");
        String accessToken = loginResponse.getBody().get("access_token");

        ResponseEntity<String> response = consumeEndpoint("/admin", accessToken);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    public void consumerAdminEndpoint_ok(){
        ResponseEntity<Map<String, String>> loginResponse = login("alexrolea93@gmail.com", "password");
        String accessToken = loginResponse.getBody().get("access_token");

        ResponseEntity<String> response = consumeEndpoint("/admin", accessToken);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void consumerAdminEndpoint_unauthorized(){
        ResponseEntity<Map<String, String>> loginResponse = login("alexrolea93@gmail.com", "password");
        String accessToken = loginResponse.getBody().get("access_token");

        ResponseEntity<String> response = consumeEndpoint("/user", accessToken);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private ResponseEntity<String> consumeEndpoint(String url, String accessToken){
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        return template.exchange(url, HttpMethod.GET, request, String.class);
    }

    private ResponseEntity<Map<String, String>> login(String username, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth("test", "test");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "password");
        map.add("username", username);
        map.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        return template.exchange(
                "/oauth/token",
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<Map<String, String>>() {
                });
    }

}
