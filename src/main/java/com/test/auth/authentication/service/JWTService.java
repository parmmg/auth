package com.test.auth.authentication.service;

import com.auth0.jwt.interfaces.Claim;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public interface JWTService {

    long EXPIRATION_DATE = 28_800_000;//8 hours
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";

    String create(Authentication auth) throws IOException;

    Map<String, Claim> getClaims(String token);

    String getUsername(String token);

    List<GrantedAuthority> getPrivileges(String token);

}
