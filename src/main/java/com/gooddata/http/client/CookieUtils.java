/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.cookie.BasicClientCookie;

/**
 * Contains handy methods .
 */
public class CookieUtils {

    private static final String SST_COOKIE_NAME = "GDCAuthSST";
    public static final String SST_COOKIE_PATH = "/gdc/account";

    private CookieUtils() { }

    /**
     * Add (or replace) super-secure cookie to http client.
     * @param sst super-secure token
     * @param httpClient http client
     * @param domain domain
     * @throws GoodDataAuthException http client does not support cookie
     */
    static void replaceSst(final String sst, final HttpClient httpClient, final String domain) {
        try {
            final AbstractHttpClient abstractHttpClient = (AbstractHttpClient) httpClient;
            final BasicClientCookie cookie = new BasicClientCookie(SST_COOKIE_NAME, sst);
            cookie.setSecure(true);
            cookie.setPath(SST_COOKIE_PATH);
            cookie.setDomain(domain);
            abstractHttpClient.getCookieStore().addCookie(cookie);
        } catch (ClassCastException e) {
            throw new GoodDataAuthException("HTTP Client does not support cookies!", e);
        }
    }
}
