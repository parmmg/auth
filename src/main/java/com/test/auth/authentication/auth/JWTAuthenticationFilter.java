package com.test.auth.authentication.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.auth.authentication.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final String FILTER_APPLIED = "__spring_security_scpf_applied";
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JWTService jwtService;

    public JWTAuthenticationFilter(ProviderManager providerManager) {
        super(providerManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            String content = IOUtils.toString(request.getReader());
            LoginRequest loginRequest = objectMapper.readValue(content, LoginRequest.class);
            final String userName = loginRequest.getUsername();
            final String password = loginRequest.getPassword();
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userName, password);
            this.setDetails(request, usernamePasswordAuthenticationToken);
            request.setAttribute(FILTER_APPLIED, true);
            return getAuthenticationManager().authenticate(usernamePasswordAuthenticationToken);
        } catch (IOException e) {
            throw new RuntimeException("RequestBody could not be read");
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        String jwtToken = jwtService.create(authResult);
        response.addHeader(JWTService.HEADER_STRING, JWTService.TOKEN_PREFIX + jwtToken);
        Map<String, Object> body = new HashMap<>();
        body.put("token", jwtToken);
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException {
        Map<String, Object> body = new HashMap<>();
        body.put("message", failed.getLocalizedMessage());
        body.put("error", failed.getCause()!=null?failed.getCause().getMessage():failed.getClass().getSimpleName());
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(401);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }

    @Getter
    @Setter
    @NoArgsConstructor
    static class LoginRequest {
        private String username;
        private String password;
    }

}
