package com.test.auth.authentication.presenter;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

@Getter
@Setter
@EqualsAndHashCode(of = "id")
@ToString(of = "id")
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PermissionPresenter {
    private String id;
    private String name;
    private boolean active;
    private String domainAction;
}
