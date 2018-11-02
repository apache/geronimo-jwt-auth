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
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import java.security.Principal;

/**
 * Validate that the injection of a {@linkplain Principal} works when using the MP-JWT feature.
 * This validates that the MP-JWT implementation is not interfering with the CDI built in
 * Principal bean.
 */
@Path("/endp")
@RequestScoped
@RolesAllowed("Tester")
public class ExtraPrincipalInjectionEndpoint {
    @Inject
    private Principal principal;

    @GET
    @Path("/verifyInjectedPrincipal")
    @Produces(MediaType.APPLICATION_JSON)
    public JsonObject verifyInjectedPrincipal(@QueryParam("upn") final String nameCheck) {
        boolean pass = false;
        String msg;
        if (principal == null) {
            msg = "principal value is null, FAIL";
        }

        else if (principal instanceof JsonWebToken) {
            msg = Claims.iss.name() + " PASS";
            pass = true;

            if (nameCheck != null && nameCheck.length() > 0) {
                if (nameCheck.equals(principal.getName())) {
                    pass = true;
                    msg = msg + "," + Claims.upn.name() + " PASS";
                }

                else {
                    pass = false;
                    msg = String.format("principal: name  %s != %s", principal.getName(), nameCheck);
                }
            }

        }

        else {
            msg = String.format("principal: JsonWebToken != %s", principal.getClass().getCanonicalName());
        }
        JsonObject result = Json.createObjectBuilder()
            .add("pass", pass)
            .add("msg", msg)
            .build();
        return result;
    }

}
