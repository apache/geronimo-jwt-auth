/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.geronimo.microprofile.impl.jwtauth.tck.jaxrs;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import org.apache.geronimo.microprofile.impl.jwtauth.cdi.GeronimoJwtAuthExtension;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("test")
@ApplicationScoped
public class AsyncEndpoint {
    @Inject
    private JsonWebToken token;

    @Inject // not perfect but CDI doesn't have any real propagation here
    private GeronimoJwtAuthExtension extension;

    @GET
    @Path("async")
    @Produces(MediaType.APPLICATION_JSON)
    public void async(@Suspended final AsyncResponse response,
                      @Context final HttpServletRequest request) {
        final CountDownLatch latchBefore = new CountDownLatch(1);
        final CountDownLatch latchResponse = new CountDownLatch(1);
        final AtomicReference<String> before = new AtomicReference<>();

        new Thread(() -> extension.execute(request, () -> {
            try {
                final String after = capture("async");
                latchBefore.countDown();
                try {
                    latchResponse.await(1, MINUTES);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                response.resume(Json.createObjectBuilder()
                        .add("before", before.get())
                        .add("after", after).build());
            } catch (final Exception e) {
                latchBefore.countDown();
                response.resume(e);
            }
        })).start();

        try {
            latchBefore.await(1, MINUTES);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        before.set(capture("sync"));
        latchResponse.countDown();
    }

    private String capture(final String marker) {
        return marker + "=" + token.getRawToken();
    }
}
