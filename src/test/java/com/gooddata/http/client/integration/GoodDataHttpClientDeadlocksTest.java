/*
 * Copyright (C) 2007-2013, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client.integration;

import com.gooddata.http.client.GoodDataHttpClient;
import com.gooddata.http.client.LoginSSTRetrievalStrategy;
import com.gooddata.http.client.SSTRetrievalStrategy;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.http.HttpHost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.junit.Test;
import org.junit.Before;
import net.jadler.Request;
import net.jadler.stubbing.Responder;
import net.jadler.stubbing.StubResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.junit.After;

import static net.jadler.Jadler.*;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import static org.junit.Assert.assertThat;
import static org.hamcrest.Matchers.*;


public class GoodDataHttpClientDeadlocksTest {
    
    private static final String LOGIN = "user@email.com";
    private static final String PASSWORD = "top secret";
    private static final String RESOURCE_PATH = "/resources";
    
    private static final int GET_RESOURCE_PROB = 60;
    private static final int GET_NEW_TT_PROB = 50;
    private static final int CONCURRENT_REQUESTS = 2;
    private static final int REQUEST_PER_THREAD = 100;
    
    private HttpHost host;
    private Random random;
    private AtomicBoolean afterSST;
    private HttpClient client;
    
    
    @Before
    public void setUp() {
        this.random = new Random();
        this.afterSST = new AtomicBoolean(false);
        initJadler();
        
          //stub for a resource http request, returns either 200 (user is authenticated, resource returned)
          //or 401 (Temporary Token not valid anymore) based on probability
        onRequest()
                .havingPathEqualTo(RESOURCE_PATH)
                .respondUsing(new Responder() {

            @Override
            public StubResponse nextResponse(final Request request) {
                if (random.nextInt(100) < GET_RESOURCE_PROB) {
                    return StubResponse.builder().status(200).build();
                }
                else {
                    return StubResponse.builder()
                            .status(401)
                            .header("WWW-Authenticate", "GoodData realm=\"GoodData API\" cookie=GDCAuthTT")
                            .build();
                }
            }
        });
        
          //stub for getting new Temporary Token. Returns either 200 and a new TT or 401 (Super Security Token
          //not valid anymore, new SST must be obtained first)
        onRequest()
                .havingPathEqualTo("/gdc/account/token")
                .respondUsing(new Responder() {

            @Override
            public StubResponse nextResponse(final Request request) {
                  // if the client tries to obtain new TT after he obtained new SST, 200 must be always returned,
                  // that's what the compareAndSet operation does
                if (afterSST.compareAndSet(true, false) || random.nextInt(100) < GET_NEW_TT_PROB) {
                    return StubResponse.builder()
                            .status(200)
                            .header("Set-Cookie", "GDCAuthTT=cookieTt; path=/gdc; secure; HttpOnly")
                            .build();
                } else {
                    return StubResponse.builder()
                            .status(401)
                            .header("WWW-Authenticate", "GoodData realm=\"GoodData API\" cookie=GDCAuthSST")
                            .build();
                }
            }
        });
        
          //stub for getting new SST
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/gdc/account/login")
                .havingHeaderEqualTo("Accept", "application/json; charset=UTF-8")
                .havingBodyEqualTo("{\"postUserLogin\":{\"login\":\"user@email.com\",\"password\":\"top secret\",\"remember\":0}}")
        .respondUsing(new Responder() {

            @Override
            public StubResponse nextResponse(final Request request) {
                afterSST.set(true); //the following request for a new TT must succeed
                return StubResponse.builder()
                        .status(200)
                        .body("{\"userLogin\":{\"profile\":\"/gdc/account/profile/asdfasdf45t4ar\",\"state\":\"/gdc/account/login/asdfasdf45t4ar\"}}", Charset.forName("UTF-8"))
                        .header("content-type", "application/json")
                        .header("Set-Cookie", "GDCAuthSST=cookieSst; path=/gdc/account; secure; HttpOnly")
                        .header("Set-Cookie", "GDCAuthTT=; path=/gdc; expires=Sat, 18-May-2013 09:10:00 GMT; secure; HttpOnly")
                        .build();
            }
        });

        this.host = new HttpHost("localhost", port(), "http");
        
        final DefaultHttpClient httpClient = new DefaultHttpClient(new PoolingClientConnectionManager());
        final SSTRetrievalStrategy sstStrategy =
                new LoginSSTRetrievalStrategy(new DefaultHttpClient(new PoolingClientConnectionManager()), this.host, LOGIN, PASSWORD);
        this.client = new GoodDataHttpClient(httpClient, sstStrategy);
    }
    
    
    @After
    public void tearDown() {
        this.client.getConnectionManager().shutdown();
        closeJadler();
    }
    
    
    @Test
    public void doIt() throws InterruptedException, ExecutionException {
        
        final ExecutorService es = Executors.newFixedThreadPool(CONCURRENT_REQUESTS);
        final Collection<Callable<Void>> tasks = new ArrayList<>(CONCURRENT_REQUESTS);
        
        for (int i = 0; i < CONCURRENT_REQUESTS; i++) {
            
            tasks.add(new Callable<Void>() {

                @Override
                public Void call() throws Exception {
                    
                    for (int i = 0; i < REQUEST_PER_THREAD; i++) {   
                        final HttpGet getProject = new HttpGet(RESOURCE_PATH);
                        System.out.println(Thread.currentThread().getName() + ": " + i);
                        final HttpResponse resp = client.execute(host, getProject);
                        assertThat(resp.getStatusLine().getStatusCode(), is(200));
                        getProject.releaseConnection();

                        EntityUtils.consume(resp.getEntity());
                    }
                    
                    return null;
                }
            });
            
        }
        
        List<Future<Void>> result = es.invokeAll(tasks);
        for (final Future<Void>f : result) {
              //if an exception occured during the execution of this thread, it will be throw during this get() call
            assertThat(f.get(), is(nullValue()));  
        }
        
        es.shutdown();
        es.awaitTermination(1000, TimeUnit.DAYS);
    }
}
