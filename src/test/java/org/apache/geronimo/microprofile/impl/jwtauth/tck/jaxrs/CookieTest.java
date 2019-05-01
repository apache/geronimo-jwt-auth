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

import static javax.ws.rs.core.MediaType.TEXT_PLAIN_TYPE;
import static org.testng.Assert.assertEquals;

import java.net.URL;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Cookie;

import org.eclipse.microprofile.jwt.tck.container.jaxrs.TCKApplication;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.annotations.Test;

// NOTE: reuses tck resources and token generation
public class CookieTest extends Arquillian {
    @Deployment(testable = false)
    public static Archive<?> war() {
        return ShrinkWrap.create(WebArchive.class, CookieTest.class.getSimpleName() + ".war")
                .addClasses(TCKApplication.class, PassthroughEndpoint.class)
                .addAsResource(CookieTest.class.getResource("/publicKey.pem"), "/publicKey.pem");
    }

    @ArquillianResource
    private URL base;

    @Test
    public void test() throws Exception {
        final Client client = ClientBuilder.newClient();
        try {
            final String token = TokenUtils.generateTokenString("/Token2.json");
            final String serverToken = client.target(base.toExternalForm())
                    .path("passthrough")
                    .request(TEXT_PLAIN_TYPE)
                    .cookie(new Cookie("Bearer", token))
                    .get(String.class);
            assertEquals(serverToken, token);
        } finally {
            client.close();
        }
    }
}
