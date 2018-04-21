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
package org.apache.geronimo.microprofile.impl.jwtauth.servlet;

import java.io.IOException;

import javax.enterprise.inject.spi.CDI;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.geronimo.microprofile.impl.jwtauth.JwtException;
import org.apache.geronimo.microprofile.impl.jwtauth.cdi.GeronimoJwtAuthExtension;
import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.apache.geronimo.microprofile.impl.jwtauth.jwt.JwtService;

public class GeronimoJwtAuthFilter implements Filter {
    private String headerName;
    private String prefix;
    private JwtService service;
    private GeronimoJwtAuthExtension extension;

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        final GeronimoJwtAuthConfig config = GeronimoJwtAuthConfig.class.cast(filterConfig.getServletContext().getAttribute(GeronimoJwtAuthConfig.class.getName()));
        headerName = config.read("geronimo.jwt-auth.header.name", "Authorization");
        prefix = config.read("geronimo.jwt-auth.header.prefix", "bearer") + " ";

        final CDI<Object> current = CDI.current();
        service = current.select(JwtService.class).get();
        extension = current.select(GeronimoJwtAuthExtension.class).get();
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        if (!HttpServletRequest.class.isInstance(request)) {
            chain.doFilter(request, response);
            return;
        }
        try {
            final JwtRequest req = new JwtRequest(service, headerName, prefix, HttpServletRequest.class.cast(request));
            extension.execute(req, () -> chain.doFilter(req, response));
        } catch (final Exception e) { // when not used with JAX-RS but directly Servlet
            Throwable current = e;
            while (current != null) {
                if (JwtException.class.isInstance(current)) {
                    final JwtException ex = JwtException.class.cast(current);
                    HttpServletResponse.class.cast(response).sendError(ex.getStatus(), ex.getMessage());
                    return;
                }
                if (current == current.getCause()) {
                    break;
                }
                current = current.getCause();
            }
            throw e;
        }
    }

    @Override
    public void destroy() {
        // no-op
    }
}
