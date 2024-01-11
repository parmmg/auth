package com.test.auth.authentication.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.test.auth.authentication.presenter.UserPresenter;
import com.test.auth.authentication.service.JWTService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class JWTServiceImpl implements JWTService {

    @Value("${spring.security.jwt.sign}")
    private String sign;

    @Override
    public String create(Authentication auth) {
        UserPresenter userPresenter = (UserPresenter) auth.getPrincipal();
        Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put("roles", auth.getAuthorities());
        return JWT.create()
                .withHeader(headerClaims)
                .withClaim("userId", userPresenter.getReferenceId())
                .withSubject(userPresenter.getUserName())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_DATE))
                .sign(Algorithm.HMAC256(sign));
    }

    @Override
    public Map<String, Claim> getClaims(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(sign);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT jwt = verifier.verify(token);
            return jwt.getClaims();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String getUsername(String token) {
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getSubject();
    }

    @Override
    public List<GrantedAuthority> getPrivileges(String token) {
        Map[] privilegesToken = JWT.decode(token).getHeaderClaim("roles").asArray(Map.class);
        List<GrantedAuthority> privileges = new ArrayList<>();
        for (Map<String, String> privilege : privilegesToken) {
            privileges.add(new SimpleGrantedAuthority(privilege.get("authority")));
        }
        return privileges;
    }

}
