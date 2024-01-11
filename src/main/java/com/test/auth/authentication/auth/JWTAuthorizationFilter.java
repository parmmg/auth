package com.test.auth.authentication.auth;

import com.auth0.jwt.interfaces.Claim;
import com.test.auth.authentication.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE)
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private static final String FILTER_APPLIED = "__spring_security_scpf_applied";
    @Autowired
    private JWTService jwtService;

    public JWTAuthorizationFilter(ProviderManager providerManager) {
        super(providerManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String tokenHeader = request.getHeader(JWTService.HEADER_STRING);
        if (tokenHeader == null) {
            chain.doFilter(request, response);
            return;
        }
        tokenHeader = tokenHeader.replaceAll("Bearer ", "");
        Map<String, Claim> claims = jwtService.getClaims(tokenHeader);
        if (claims == null) {
            throw new AuthorizationServiceException("Invalid Token");
        }
        String username = jwtService.getUsername(tokenHeader);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username,
                tokenHeader, jwtService.getPrivileges(tokenHeader));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setAttribute(FILTER_APPLIED, true);
        chain.doFilter(request, response);
    }
}
