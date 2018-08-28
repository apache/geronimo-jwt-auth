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
package org.apache.geronimo.microprofile.impl.jwtauth.jwt;

import static java.util.Optional.ofNullable;

import java.net.HttpURLConnection;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.JsonNumber;
import javax.json.JsonObject;

import org.apache.geronimo.microprofile.impl.jwtauth.JwtException;
import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.config.Names;

@ApplicationScoped
public class DateValidator {
    @Inject
    private GeronimoJwtAuthConfig config;
    private boolean expirationMandatory;
    private boolean issuedAtTimeMandatory;
    private long tolerance;

    @PostConstruct
    private void init() {
        expirationMandatory = Boolean.parseBoolean(config.read("exp.required", "true"));
        issuedAtTimeMandatory = Boolean.parseBoolean(config.read("iat.required", "true"));
        tolerance = Long.parseLong(config.read("date.tolerance",
                Long.toString(ofNullable(config.read("org.eclipse.microprofile.authentication.JWT.clockSkew", null))
                        .map(Long::parseLong)
                        .orElse(60L))));
    }

    void checkInterval(final JsonObject payload) {
        long now = -1;

        final JsonNumber exp = payload.getJsonNumber(Claims.exp.name());
        if (exp == null) {
            if (expirationMandatory) {
                throw new JwtException("No exp in the JWT", HttpURLConnection.HTTP_UNAUTHORIZED);
            }
        } else {
            final long expValue = exp.longValue();
            now = now();
            if (expValue < now - tolerance) {
                throw new JwtException("Token expired", HttpURLConnection.HTTP_UNAUTHORIZED);
            }
        }

        final JsonNumber iat = payload.getJsonNumber(Claims.iat.name());
        if (iat == null) {
            if (issuedAtTimeMandatory) {
                throw new JwtException("No iat in the JWT", HttpURLConnection.HTTP_UNAUTHORIZED);
            }
        } else {
            final long iatValue = iat.longValue();
            if (now < 0) {
                now = now();
            }
            if (iatValue > now + tolerance) {
                throw new JwtException("Token issued after current time", HttpURLConnection.HTTP_UNAUTHORIZED);
            }
        }
    }

    private long now() {
        return System.currentTimeMillis() / 1000;
    }
}
