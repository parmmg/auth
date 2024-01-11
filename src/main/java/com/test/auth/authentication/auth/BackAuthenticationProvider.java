package com.test.auth.authentication.auth;

import com.test.auth.authentication.presenter.UserPresenter;
import com.test.auth.authentication.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class BackAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserService authServiceClient;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserPresenter userPresenter = authServiceClient.findUserByUserName(authentication.getPrincipal().toString());
        if (userPresenter == null || !passwordEncoder.matches(authentication.getCredentials().toString(), userPresenter.getPassword())) {
            throw new UsernameNotFoundException("Usuario o contraseña incorrecta");
        }
        if (!userPresenter.isActive()) {
            throw new DisabledException("Usuario no se encuentra activo");
        }
        Set<GrantedAuthority> permissions = new HashSet<>();
        userPresenter.getRolePresenters().forEach(rolePresenter -> rolePresenter.getPermissionPresenters().forEach(permissionPresenter -> permissions.add(new SimpleGrantedAuthority(permissionPresenter.getDomainAction()))));
        if (permissions.isEmpty()) {
            throw new LockedException("Usuario no tiene permisos");
        }
        return new UsernamePasswordAuthenticationToken(userPresenter, null, permissions);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }

}
