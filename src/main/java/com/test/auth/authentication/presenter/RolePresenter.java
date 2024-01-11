package com.test.auth.authentication.presenter;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@EqualsAndHashCode(of = "id")
@ToString(of = "id")
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RolePresenter {
    private String id;
    private String name;
    @Builder.Default
    private Set<PermissionPresenter> permissionPresenters = new HashSet<>();
}
