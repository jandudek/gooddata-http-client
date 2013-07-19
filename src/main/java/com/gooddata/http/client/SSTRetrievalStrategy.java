/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.HttpHost;
import org.apache.http.impl.client.AbstractHttpClient;

/**
 * Interface for class which encapsulates SST retrival.
 */
public interface SSTRetrievalStrategy {

    /**
     * Sets SST cookie to HTTP client.
     * @return SST
     */
    void obtainSst(AbstractHttpClient httpClient, HttpHost httpHost);

}
