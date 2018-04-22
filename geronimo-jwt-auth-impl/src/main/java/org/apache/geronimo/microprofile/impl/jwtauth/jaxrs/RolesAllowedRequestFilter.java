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
package org.apache.geronimo.microprofile.impl.jwtauth.jaxrs;

import static java.util.Collections.emptyMap;

import java.io.IOException;
import java.util.Collection;

import javax.json.Json;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

class RolesAllowedRequestFilter implements ContainerRequestFilter {
    private final Response forbidden = Response
            .status(Response.Status.FORBIDDEN)
            .entity(Json.createObjectBuilder(emptyMap()).add("message", "you are not allowed to access that endpoint").build())
            .build();

    private final boolean denyAll;
    private final boolean permitAll;
    private final Collection<String> roles;

    RolesAllowedRequestFilter(final boolean denyAll, final boolean permitAll, final Collection<String> roles) {
        this.denyAll = denyAll;
        this.permitAll = permitAll;
        this.roles = roles;
    }

    @Override
    public void filter(final ContainerRequestContext context) throws IOException {
        if (denyAll) {
            context.abortWith(forbidden);
        } else if (!permitAll) {
            final SecurityContext securityContext = context.getSecurityContext();
            if (securityContext == null || roles.stream().noneMatch(securityContext::isUserInRole)) {
                context.abortWith(forbidden);
            }
        }
    }
}
