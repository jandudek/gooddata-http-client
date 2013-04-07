/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

/**
 * GoodData authentication exception.
 */
public class GoodDataAuthException extends RuntimeException {

    public GoodDataAuthException() { }

    public GoodDataAuthException(String s) {
        super(s);
    }

    public GoodDataAuthException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public GoodDataAuthException(Throwable throwable) {
        super(throwable);
    }

    public GoodDataAuthException(String s, Throwable throwable, boolean b, boolean b1) {
        super(s, throwable, b, b1);
    }
}
