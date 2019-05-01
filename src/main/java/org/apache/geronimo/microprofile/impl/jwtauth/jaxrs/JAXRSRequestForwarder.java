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

import javax.annotation.Priority;
import javax.enterprise.context.Dependent;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;

import org.apache.geronimo.microprofile.impl.jwtauth.servlet.JwtRequest;

@Provider
@Dependent
@Priority(Priorities.AUTHENTICATION - 1)
public class JAXRSRequestForwarder implements ContainerRequestFilter {
    @Context
    private HttpServletRequest request;

    @Override
    public void filter(final ContainerRequestContext requestContext) {
        final JwtRequest jwtRequest = JwtRequest.class.cast(request.getAttribute(JwtRequest.class.getName()));
        if (jwtRequest == null) {
            return;
        }
        final String value = requestContext.getHeaders().getFirst(jwtRequest.getHeaderName());
        if (value != null) {
            jwtRequest.setAttribute(JAXRSRequestForwarder.class.getName() + ".header", value);
        }
    }
}
