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

import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toList;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import java.util.stream.Stream;

import javax.security.auth.Subject;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.geronimo.microprofile.impl.jwtauth.JwtException;
import org.apache.geronimo.microprofile.impl.jwtauth.jwt.JwtParser;
import org.eclipse.microprofile.jwt.JsonWebToken;

public class JwtRequest extends HttpServletRequestWrapper implements TokenAccessor {
    private final Supplier<JsonWebToken> tokenExtractor;
    private final String headerName;
    private volatile JsonWebToken token; // cache for perf reasons

    public JwtRequest(final JwtParser service, final String header, final String cookie,
                      final String prefix, final HttpServletRequest request) {
        super(request);
        this.headerName = header;

        this.tokenExtractor = () -> {
            if (token != null) {
                return token;
            }

            synchronized (this) {
                if (token != null) {
                    return token;
                }

                final Object existing = getAttribute(JsonWebToken.class.getName());
                if (existing != null) {
                    token = JsonWebToken.class.isInstance(existing) ?
                            JsonWebToken.class.cast(existing) :
                            service.parse(String.valueOf(existing));
                    return token;
                }

                boolean fromHeader = true;
                String auth = String.class.cast(
                    getAttribute("org.apache.geronimo.microprofile.impl.jwtauth.jaxrs.JAXRSRequestForwarder.header"));
                if (auth == null) {
                    auth = getHeader(header);
                }
                if (auth == null) {
                    final Cookie[] cookies = getCookies();
                    if (cookies != null) {
                        fromHeader = false;
                        auth = Stream.of(cookies)
                            .filter(it -> cookie.equalsIgnoreCase(it.getName()))
                            .findFirst()
                            .map(Cookie::getValue)
                            .orElse(null);
                    }
                }
                if (auth == null || auth.isEmpty()) {
                    throw new JwtException("No " + header + " header", HttpServletResponse.SC_UNAUTHORIZED);
                }
                if (fromHeader) {
                    if (!auth.toLowerCase(Locale.ROOT).startsWith(prefix)) {
                        throw new JwtException("No prefix " + prefix + " in header " + header, HttpServletResponse.SC_UNAUTHORIZED);
                    }
                    token = service.parse(auth.substring(prefix.length()));
                } else {
                    token = service.parse(auth.startsWith(prefix) ? auth.substring(prefix.length()) : auth);
                }
                setAttribute(JsonWebToken.class.getName(), token);
                return token;
            }
        };

        // integration hook if needed
        setAttribute(JwtRequest.class.getName(), this);
        setAttribute(JsonWebToken.class.getName() + ".supplier", tokenExtractor);
        setAttribute(Principal.class.getName() + ".supplier", tokenExtractor);
        // not portable but used by some servers like tomee
        setAttribute("javax.security.auth.subject.callable", (Callable<Subject>) () -> {
            final Set<Principal> principals = new LinkedHashSet<>();
            final JsonWebToken namePrincipal = tokenExtractor.get();
            principals.add(namePrincipal);
            principals.addAll(namePrincipal.getGroups().stream().map(role -> (Principal) () -> role).collect(toList()));
            return new Subject(true, principals, emptySet(), emptySet());
        });
    }

    public String getHeaderName() {
        return headerName;
    }

    public TokenAccessor asTokenAccessor() {
        return this;
    }

    @Override
    public JsonWebToken getToken() {
        return tokenExtractor.get();
    }

    @Override
    public Principal getUserPrincipal() {
        return tokenExtractor.get();
    }

    @Override
    public boolean isUserInRole(final String role) {
        return tokenExtractor.get().getGroups().contains(role);
    }

    @Override
    public String getAuthType() {
        return "MP-JWT";
    }
}
