package com.test.auth.authentication.presenter;

import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPresenter {

    private String password;
    private String userName;
    private String fullName;
    private String dni;
    private String referenceId;
    private String pin;
    private boolean active;
    @Builder.Default
    private boolean sessionActive = false;
    @Builder.Default
    private Set<RolePresenter> rolePresenters = new HashSet<>();
}
