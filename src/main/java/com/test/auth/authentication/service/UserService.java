package com.test.auth.authentication.service;

import com.test.auth.authentication.presenter.UserPresenter;

public interface UserService {

    UserPresenter findUserByUserName (String userName);

}
