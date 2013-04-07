/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.client.HttpClient;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.DefaultHttpClient;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class CookieUtilsTest {

    public static final String DOMAIN = "server.com";
    public static final String SST = "sst_token";
    public HttpClient httpClient;

    @Test
    public void replaceSst() {
        httpClient = new DefaultHttpClient();
        CookieUtils.replaceSst(SST, httpClient, DOMAIN);
        checkCookie();
    }

    @Test(expected = GoodDataAuthException.class)
    public void replaceSst_doesNotSupportCookies() {
        httpClient = mock(HttpClient.class);
        CookieUtils.replaceSst(SST, httpClient, DOMAIN);
    }

    private void checkCookie() {
        final Cookie cookie = ((DefaultHttpClient) httpClient).getCookieStore().getCookies().get(0);
        assertThat(DOMAIN, is(cookie.getDomain()));
        assertThat(SST, is(cookie.getValue()));
        assertThat(true, is(cookie.isSecure()));
        assertThat("/gdc/account", is(cookie.getPath()));
        assertThat("GDCAuthSST", is(cookie.getName()));
    }
}
