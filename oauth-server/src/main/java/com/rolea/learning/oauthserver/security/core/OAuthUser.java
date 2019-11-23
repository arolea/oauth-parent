package com.rolea.learning.oauthserver.security.core;

import com.rolea.learning.oauthserver.domain.UserAccount;
import com.rolea.learning.oauthserver.domain.UserRole;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;
import java.util.stream.Collectors;

@Data
public class OAuthUser extends User {

    private Long userId;
    private List<UserRole> userRoles;

    public OAuthUser(UserAccount account) {
        super(
                account.getEmail(),
                account.getPassword(),
                account.getEnabled(),
                true,
                true,
                true,
                OAuthUser.getAuthorities(account.getUserRoles())
        );
        this.userId = account.getId();
        this.userRoles = account.getUserRoles();
    }

    private static List<GrantedAuthority> getAuthorities(List<UserRole> roles){
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());
    }

}
