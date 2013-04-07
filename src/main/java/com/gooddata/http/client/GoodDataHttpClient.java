/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AUTH;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;

/**
 * <p>Http client with ability to handle GoodData authentication.</p>
 *
 * <h3>Usage</h3>
 *
 * <h4>Authentication using login</h4>
 * <pre>
 * // create HTTP client with your settings
 * HttpClient httpClient = ...
 *
 * // create login strategy, which wil obtain SST via login
 * SstStrategy sstStrategy = new LoginSstStrategy("user@domain.com", "my secret");
 *
 * // wrap your HTTP client into GoodData HTTP client
 * HttpClient client = new GoodDataHttpClient(httpClient, sstStrategy);
 *
 * // use GoodData HTTP client
 * HttpGet getProject = new HttpGet("/gdc/projects");
 * getProject.addHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());
 * HttpResponse getProjectResponse = client.execute(httpHost, getProject);
 * </pre>
 *
 * <h4>Authentication using super-secure token (SST)</h4>
 *
 * <pre>
 * // create HTTP client
 * HttpClient httpClient = ...
 *
 * // create login strategy (you must somehow obtain SST)
 * SstStrategy sstStrategy = new SimpleSstStrategy("my super-secure token");
 *
 * // wrap your HTTP client into GoodData HTTP client
 * HttpClient client = new GoodDataHttpClient(httpClient, sstStrategy);
 *
 * // use GoodData HTTP client
 * HttpGet getProject = new HttpGet("/gdc/projects");
 * getProject.addHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());
 * HttpResponse getProjectResponse = client.execute(httpHost, getProject);
 * </pre>
 */
public class GoodDataHttpClient implements HttpClient {

    private static final String TOKEN_URL = "/gdc/account/token";
    public static final String COOKIE_GDC_AUTH_TT = "cookie=GDCAuthTT";
    public static final String COOKIE_GDC_AUTH_SST = "cookie=GDCAuthSST";

    private enum GoodDataChallengeType {
        SST, TT, UNKNOWN;
    }

    private final Log log = LogFactory.getLog(getClass());

    private final HttpClient httpClient;

    private final SstStrategy sstStrategy;

    /**
     * Construct object.
     * @param httpClient Http client
     * @param sstStrategy super-secure token (SST) obtaining strategy
     */
    public GoodDataHttpClient(final HttpClient httpClient, final SstStrategy sstStrategy) {
        this.httpClient = httpClient;
        this.sstStrategy = sstStrategy;
    }

    /**
     * Construct object.
     * @param sstStrategy super-secure token (SST) obtaining strategy
     */
    public GoodDataHttpClient(final SstStrategy sstStrategy) {
        this(new DefaultHttpClient(), sstStrategy);
    }

    private GoodDataChallengeType identifyGoodDataChallenge(final HttpResponse response) {
        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
            final Header[] headers = response.getHeaders(AUTH.WWW_AUTH);
            if (headers != null) {
                for (final Header header : headers) {
                    final String challenge = header.getValue();
                    if (challenge.contains(COOKIE_GDC_AUTH_SST)) {
                        return GoodDataChallengeType.SST;
                    } else if (challenge.contains(COOKIE_GDC_AUTH_TT)) {
                        return GoodDataChallengeType.TT;
                    }
                }
            }
        }
        return GoodDataChallengeType.UNKNOWN;
    }

    private HttpResponse handleResponse(final HttpHost httpHost, final HttpRequest request, final HttpResponse originalResponse, final HttpContext context) throws IOException {
        switch (identifyGoodDataChallenge(originalResponse)) {
            case SST:
                EntityUtils.consume(originalResponse.getEntity());
                authenticate(httpHost);
                break;
            case TT:
                EntityUtils.consume(originalResponse.getEntity());
                if (!refreshTt(httpHost)) {
                    authenticate(httpHost);
                }
                break;
            default:
                return originalResponse;
        }
        return httpClient.execute(httpHost, request, context);
    }

    private void authenticate(final HttpHost httpHost) {
        sstStrategy.obtainSst(httpClient, httpHost);
        if (!refreshTt(httpHost)) {
            throw new GoodDataAuthException("Unable to obtain TT after successfully obtained SST");
        }
    }

    /**
     * Refresh temporary token.
     * @param httpHost HTTP host
     * @return
     * <ul>
     *     <li><code>true</code> TT refresh successful</li>
     *     <li><code>false</code> TT refresh unsuccessful (SST expired)</li>
     * </ul>
     * @throws GoodDataAuthException error
     */
    private boolean refreshTt(final HttpHost httpHost) {
        log.debug("Obtaining TT");
        final boolean result;
        final HttpGet getTT = new HttpGet(TOKEN_URL);
        try {
            final HttpResponse response = httpClient.execute(httpHost, getTT);
            final int status = response.getStatusLine().getStatusCode();
            switch (status) {
                case HttpStatus.SC_OK:
                    result = true;
                    break;
                case HttpStatus.SC_UNAUTHORIZED:
                    result = false;
                    break;
                default:
                    throw new GoodDataAuthException("Unable to obtain TT, HTTP status: " + status);
            }
        } catch (IOException e) {
            throw new GoodDataAuthException("Error during temporary token refresh: " + e.getMessage(), e);
        } finally {
            getTT.releaseConnection();
        }
        return result;
    }

    @Override
    public HttpParams getParams() {
        return httpClient.getParams();
    }

    @Override
    public ClientConnectionManager getConnectionManager() {
        return httpClient.getConnectionManager();
    }

    @Override
    public HttpResponse execute(HttpHost target, HttpRequest request) throws IOException, ClientProtocolException {
        HttpContext defaultContext = null;
        return execute(target, request, defaultContext);
    }

    @Override
    public <T> T execute(HttpHost target, HttpRequest request, ResponseHandler<? extends T> responseHandler) throws IOException {
        return execute(target, request, responseHandler, null);
    }

    @Override
    public <T> T execute(HttpHost target, HttpRequest request, ResponseHandler<? extends T> responseHandler, HttpContext context) throws IOException {
        HttpResponse resp = execute(target, request, context);
        return responseHandler.handleResponse(resp);
    }

    @Override
    public HttpResponse execute(HttpUriRequest request) throws IOException {
        final HttpContext context = null;
        return execute(request, context);
    }

    @Override
    public HttpResponse execute(HttpUriRequest request, HttpContext context) throws IOException {
        final URI uri = request.getURI();
        final HttpHost httpHost = new HttpHost(uri.getHost(), uri.getPort(),
                uri.getScheme());
        return execute(httpHost, request, context);
    }

    @Override
    public <T> T execute(HttpUriRequest request, ResponseHandler<? extends T> responseHandler) throws IOException {
        return execute(request, responseHandler, null);
    }

    @Override
    public <T> T execute(HttpUriRequest request, ResponseHandler<? extends T> responseHandler, HttpContext context)
            throws IOException {
        final HttpResponse resp = execute(request, context);
        return responseHandler.handleResponse(resp);
    }

    @Override
    public HttpResponse execute(HttpHost target, HttpRequest request, HttpContext context) throws IOException, ClientProtocolException {
        return handleResponse(target, request, httpClient.execute(target, request, context), context);
    }
}
