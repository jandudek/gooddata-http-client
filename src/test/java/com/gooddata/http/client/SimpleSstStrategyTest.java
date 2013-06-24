/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.HttpHost;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.DefaultHttpClient;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;


public class SimpleSstStrategyTest {

    public static final String TOKEN = "sst token";
    public static final String DOMAIN = "server.com";

    private HttpHost host;

    private SimpleSSTRetrievalStrategy sstStrategy;

    private DefaultHttpClient httpClient;

    @Before
    public void setUp() {
        httpClient = new DefaultHttpClient();
        host = new HttpHost("server.com", 666);
    }

    @Test
    public void obtainSst() {
        sstStrategy = new SimpleSSTRetrievalStrategy(TOKEN);
        sstStrategy.obtainSst(httpClient, host);

        checkCookie();
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_nullSst() {
        new SimpleSSTRetrievalStrategy(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void obtainSst_null() {
        sstStrategy = new SimpleSSTRetrievalStrategy();
        sstStrategy.obtainSst(httpClient, host);
    }

    @Test
    public void setSst() {
        sstStrategy = new SimpleSSTRetrievalStrategy();
        sstStrategy.setSst(TOKEN);
        sstStrategy.obtainSst(httpClient, host);

        checkCookie();
    }

    private void checkCookie() {
        final Cookie cookie = httpClient.getCookieStore().getCookies().get(0);
        assertThat(DOMAIN, is(cookie.getDomain()));
        assertThat(TOKEN, is(cookie.getValue()));
        assertThat(true, is(cookie.isSecure()));
        assertThat("/gdc/account", is(cookie.getPath()));
        assertThat("GDCAuthSST", is(cookie.getName()));
    }
}
