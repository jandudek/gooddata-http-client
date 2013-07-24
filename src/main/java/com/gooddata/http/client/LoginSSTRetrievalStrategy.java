/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.cookie.SM;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.cookie.BrowserCompatSpec;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;
import java.util.List;

/**
 * This strategy obtains super-secure token via login.
 */
public class LoginSSTRetrievalStrategy implements SSTRetrievalStrategy {

    public static final String LOGIN_URL = "/gdc/account/login";

    private final Log log = LogFactory.getLog(getClass());

    private final ObjectMapper mapper = new ObjectMapper();

    private final String login;

    private final String password;

    private final HttpHost httpHost;

    private final AbstractHttpClient httpClient;

    public LoginSSTRetrievalStrategy(final AbstractHttpClient httpClient, final HttpHost httpHost, final String login, final String password) {
        this.login = login;
        this.password = password;
        this.httpHost = httpHost;
        this.httpClient = httpClient;
    }

    @Override
    public String obtainSst() {
        log.debug("Obtaining STT");
        final HttpPost postLogin = new HttpPost(LOGIN_URL);
        final LoginDTO loginDto = new LoginDTO(login, password, 0);
        try {
            final HttpEntity requestEntity = new StringEntity(mapper.writeValueAsString(loginDto), ContentType.APPLICATION_JSON);
            postLogin.setEntity(requestEntity);
            final HttpResponse response = httpClient.execute(httpHost, postLogin);
            int status = response.getStatusLine().getStatusCode();
            if (status != HttpStatus.SC_OK) {
                throw new GoodDataAuthException("Unable to login: " + status);
            }
            String sst = null;
            CookieSpec cookieSpec = new BrowserCompatSpec();
            CookieOrigin origin = new CookieOrigin(httpHost.getHostName(), httpHost.getPort(), "/gdc", true);
            for (Header header : response.getHeaders(SM.SET_COOKIE)) {
                List<Cookie> cookies = cookieSpec.parse(header, origin);
                if (cookies.size() > 0) {
                    sst = cookies.get(0).getValue();
                    break;
                }
            }
            if (sst == null) {
                throw new GoodDataAuthException("Unable to login. Missing SST Set-Cookie header.");
            }
            return sst;
        } catch (IOException e) {
            throw new GoodDataAuthException("Unable to login: " + e.getMessage(), e);
        } catch (MalformedCookieException e) {
            throw new GoodDataAuthException("Unable to login. Malformed Set-Cookie header.");
        } finally {
            postLogin.releaseConnection();
        }
    }
}
