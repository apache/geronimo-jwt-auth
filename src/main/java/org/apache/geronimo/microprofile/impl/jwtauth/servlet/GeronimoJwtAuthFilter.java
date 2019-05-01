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

import static java.util.stream.Collectors.toSet;

import java.io.IOException;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Stream;

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
import org.apache.geronimo.microprofile.impl.jwtauth.jwt.JwtParser;

public class GeronimoJwtAuthFilter implements Filter {
    private String headerName;
    private String cookieName;
    private String prefix;
    private JwtParser service;
    private GeronimoJwtAuthExtension extension;
    private Collection<String> publicUrls;

    @Override
    public void init(final FilterConfig filterConfig) {
        final CDI<Object> current = CDI.current();
        service = current.select(JwtParser.class).get();
        extension = current.select(GeronimoJwtAuthExtension.class).get();

        final GeronimoJwtAuthConfig config = current.select(GeronimoJwtAuthConfig.class).get();
        headerName = config.read("header.name", "Authorization");
        cookieName = config.read("cookie.name", "Bearer");
        prefix = Optional.of(config.read("header.prefix", "bearer"))
                .filter(s -> !s.isEmpty()).map(s -> s + " ")
                .orElse("");
        publicUrls = Stream.of(config.read("filter.publicUrls", "").split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(toSet());
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        if (!HttpServletRequest.class.isInstance(request)) {
            chain.doFilter(request, response);
            return;
        }

        final HttpServletRequest httpServletRequest = HttpServletRequest.class.cast(request);
        if (!publicUrls.isEmpty()) {
            final String current = httpServletRequest.getRequestURI().substring(httpServletRequest.getContextPath().length());
            if (publicUrls.stream().anyMatch(current::startsWith)) {
                chain.doFilter(request, response);
                return;
            }
        }

        try {
            final JwtRequest req = new JwtRequest(service, headerName, cookieName, prefix, httpServletRequest);
            extension.execute(req.asTokenAccessor(), () -> chain.doFilter(req, response));
        } catch (final Exception e) { // when not used with JAX-RS but directly Servlet
            final HttpServletResponse httpServletResponse = HttpServletResponse.class.cast(response);
            if (!httpServletResponse.isCommitted()) {
                Throwable current = e;
                while (current != null) {
                    if (JwtException.class.isInstance(current)) {
                        final JwtException ex = JwtException.class.cast(current);
                        httpServletResponse.sendError(ex.getStatus(), ex.getMessage());
                        return;
                    }
                    if (current == current.getCause()) {
                        break;
                    }
                    current = current.getCause();
                }
            }
            throw e;
        }
    }

    @Override
    public void destroy() {
        // no-op
    }
}
