/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;

import static org.apache.commons.lang.Validate.notNull;

/**
 * Provides super-secure token (SST)
 */
public class SimpleSstStrategy implements SstStrategy {

    private String sst;

    /**
     * Creates new instance with empty SST.
     */
    public SimpleSstStrategy() { }

    /**
     *
     * @param sst super-secure token (SST)
     */
    public SimpleSstStrategy(final String sst) {
        setSst(sst);
    }

    @Override
    public void obtainSst(final HttpClient httpClient, final HttpHost host) {
        notNull(sst, "No SST set.");
        CookieUtils.replaceSst(sst, httpClient, host.getHostName());
    }

    /**
     * Sets new SST.
     * @param sst new SST
     * @throws IllegalArgumentException if <code>sst</code> is null
     */
    public void setSst(final String sst) {
        notNull(sst, "Super-secure token cannot be null");
        this.sst = sst;
    }
}
