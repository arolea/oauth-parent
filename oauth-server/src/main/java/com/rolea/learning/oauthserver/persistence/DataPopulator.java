package com.rolea.learning.oauthserver.persistence;

import com.rolea.learning.oauthserver.domain.UserAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.rolea.learning.oauthserver.domain.UserRole.ROLE_ADMIN;
import static com.rolea.learning.oauthserver.domain.UserRole.ROLE_USER;
import static java.util.Arrays.asList;

/**
 * Populates the DB with sample users
 * USER: alexrolea1@gmail.com / password
 * ADMIN: alexrolea93.com / password
 */
@Configuration
public class DataPopulator {

    private static final Logger LOG = LoggerFactory.getLogger(DataPopulator.class);

    @Autowired
    private UserAccountRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initDatabase(){
        return (args) -> {
            LOG.info("Starting DB init");
            repository.save(UserAccount.builder()
                    .email("alexrolea1@gmail.com")
                    .password(passwordEncoder.encode("password"))
                    .userRoles(asList(ROLE_USER))
                    .enabled(Boolean.TRUE)
                    .build());
            repository.save(UserAccount.builder()
                    .email("alexrolea93@gmail.com")
                    .password(passwordEncoder.encode("password"))
                    .userRoles(asList(ROLE_ADMIN))
                    .enabled(Boolean.TRUE)
                    .build());
            repository.findAll()
                    .forEach(System.out::println);
            LOG.info("Finished DB init");
        };
    }

}
