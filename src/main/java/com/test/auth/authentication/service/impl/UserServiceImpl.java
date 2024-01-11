package com.test.auth.authentication.service.impl;

import com.test.auth.authentication.presenter.PermissionPresenter;
import com.test.auth.authentication.presenter.RolePresenter;
import com.test.auth.authentication.presenter.UserPresenter;
import com.test.auth.authentication.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Set;


@Service
public class UserServiceImpl implements UserService {

    @Value("${config.user.name}")
    private String name;
    @Value("${config.user.password}")
    private String pass;
    @Value("${config.user.role}")
    private String role;
    @Value("${config.user.permission}")
    private String permission;

    @Override
    public UserPresenter findUserByUserName(String userName) {
        if (userName.equals(name)) {
            return UserPresenter.builder()
                    .userName(name)
                    .active(true)
                    .password(pass)
                    .rolePresenters(Set.of(RolePresenter.builder()
                            .name(role)
                            .permissionPresenters(Set.of(PermissionPresenter.builder()
                                    .active(true)
                                    .domainAction(permission)
                                    .name(permission)
                                    .build()))
                            .build()))
                    .build();
        }
        return null;
    }
}
