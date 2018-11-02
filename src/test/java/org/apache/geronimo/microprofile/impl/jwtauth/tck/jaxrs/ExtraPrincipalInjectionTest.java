/*
 * Copyright (c) 2016-2018 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.apache.geronimo.microprofile.impl.jwtauth.tck.jaxrs;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.PrincipalInjectionEndpoint;
import org.eclipse.microprofile.jwt.tck.container.jaxrs.TCKApplication;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;

import static org.eclipse.microprofile.jwt.tck.TCKConstants.TEST_GROUP_CDI_PROVIDER;

/**
 * Tests that the {@linkplain java.security.Principal} can be used as an injection type
 * for the authenticated user
 */
public class ExtraPrincipalInjectionTest extends Arquillian {

    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive
     * @return the base base web application archive
     * @throws IOException - on resource failure
     */
    @Deployment(testable=true)
    public static WebArchive createDeployment() throws IOException {
        URL publicKey = PrincipalInjectionEndpoint.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
            .create(WebArchive.class, "ExtraPrincipalInjectionEndpoint.war")
            .addAsResource(publicKey, "/publicKey.pem")
            .addClass(ExtraPrincipalInjectionEndpoint.class)
            .addClass(TCKApplication.class)
            .addAsWebInfResource("beans.xml", "beans.xml")
            ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
        description = "Verify that the injected authenticated principal is as expected")
    public void verifyInjectedPrincipal() throws Exception {
        Reporter.log("Begin verifyInjectedPrincipal, baseURL="+baseURL.toExternalForm() );
        String uri = baseURL.toExternalForm() + "endp/verifyInjectedPrincipal";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri);

        final String token = TokenUtils.generateTokenString("/Token1.json", null, new HashMap<>());
        Response response = echoEndpointTarget.queryParam("upn", "jdoe@example.com").request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
        description = "Verify that the injected authenticated principal is as expected with a different token")
    public void verifyInjectedPrincipal2() throws Exception {
        Reporter.log("Begin verifyInjectedPrincipal, baseURL="+baseURL.toExternalForm() );
        String uri = baseURL.toExternalForm() + "endp/verifyInjectedPrincipal";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
            .target(uri);

        final String token = TokenUtils.generateTokenString("/Token2.json", null, new HashMap<>());
        Response response = echoEndpointTarget.queryParam("upn", "jdoe2@example.com").request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

}
