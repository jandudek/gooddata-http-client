/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.codehaus.jackson.annotate.JsonCreator;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonTypeInfo;
import org.codehaus.jackson.annotate.JsonTypeName;

/**
 * Login DTO. Encapsulates login and password.
 */
@JsonTypeInfo(include= JsonTypeInfo.As.WRAPPER_OBJECT, use= JsonTypeInfo.Id.NAME)
@JsonTypeName("postUserLogin")
public class LoginDTO {

    private final String login;

    private final String password;

    private final Integer remember;

    /**
     * Constructs object.
     * @param login login
     * @param password password
     * @param remember token validity period (0 - short period, 1 - long period)
     */
    @JsonCreator
    public LoginDTO(
            @JsonProperty("login") final String login,
            @JsonProperty("password") final String password,
            @JsonProperty("remember") final Integer remember) {
        this.login = login;
        this.password = password;
        this.remember = remember;
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    public Integer getRemember() {
        return remember;
    }
}
