/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.HttpHost;
import org.apache.http.impl.client.AbstractHttpClient;

import static org.apache.commons.lang.Validate.notNull;

/**
 * Provides super-secure token (SST)
 */
public class SimpleSSTRetrievalStrategy implements SSTRetrievalStrategy {

    private final String sst;

    /**
     * Creates new instance.
     * @param sst super-secure token (SST)
     */
    public SimpleSSTRetrievalStrategy(final String sst) {
        this.sst = sst;
    }

    @Override
    public void obtainSst(AbstractHttpClient httpClient, HttpHost httpHost) {
        notNull(sst, "No SST set.");
        CookieUtils.replaceSst(sst, httpClient, httpHost.getHostName());
    }

}
