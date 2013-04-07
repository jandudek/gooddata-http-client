/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;

/**
 * This strategy obtains super-secure token via login.
 */
public class LoginSstStrategy implements SstStrategy {

    public static final String LOGIN_URL = "/gdc/account/login";

    private final Log log = LogFactory.getLog(getClass());

    private final ObjectMapper mapper = new ObjectMapper();

    private final String login;

    private final String password;

    public LoginSstStrategy(final String login, final String password) {
        this.login = login;
        this.password = password;
    }

    @Override
    public void obtainSst(final HttpClient httpClient, final HttpHost httpHost) {
        log.debug("Obtaining STT");
        final HttpPost postLogin = new HttpPost(LOGIN_URL);
        final LoginDto loginDto = new LoginDto(login, password, 0);
        try {
            final HttpEntity requestEntity = new StringEntity(mapper.writeValueAsString(loginDto), ContentType.APPLICATION_JSON);
            postLogin.setEntity(requestEntity);
            final HttpResponse response = httpClient.execute(httpHost, postLogin);
            int status = response.getStatusLine().getStatusCode();
            if (status != HttpStatus.SC_OK) {
                throw new GoodDataAuthException("Unable to login: " + status);
            }
        } catch (IOException e) {
            throw new GoodDataAuthException("Unable to login: " + e.getMessage(), e);
        } finally {
            postLogin.releaseConnection();
        }
    }
}
