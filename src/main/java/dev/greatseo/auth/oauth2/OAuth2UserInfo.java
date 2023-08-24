package dev.greatseo.auth.oauth2;

import dev.greatseo.auth.entity.User;
import dev.greatseo.auth.enums.AuthProvider;
import dev.greatseo.auth.enums.Role;
import org.springframework.security.oauth2.core.user.OAuth2User;

import lombok.AllArgsConstructor;
import lombok.Getter;
import java.util.Map;

@Getter
@AllArgsConstructor
public abstract class OAuth2UserInfo {

    protected Map<String, Object> attributes;

    public abstract String getOAuth2Id();
    public abstract String getEmail();
    public abstract String getName();
}
