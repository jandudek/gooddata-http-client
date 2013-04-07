/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;

/**
 * Interface for class which encapsulates obtaining SST.
 */
public interface SstStrategy {

    /**
     * Sets SST cookie to HTTP client.
     * @param httpClient HTTP client
     * @param host host
     */
    void obtainSst(HttpClient httpClient, HttpHost host);

}
