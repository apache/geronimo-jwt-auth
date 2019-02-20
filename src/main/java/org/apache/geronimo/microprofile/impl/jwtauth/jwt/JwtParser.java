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

import static java.util.Collections.emptyMap;

import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;
import java.util.Base64;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReaderFactory;
import javax.json.JsonString;

import org.apache.geronimo.microprofile.impl.jwtauth.JwtException;
import org.apache.geronimo.microprofile.impl.jwtauth.cdi.GeronimoJwtAuthExtension;
import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

@ApplicationScoped
public class JwtParser {
    @Inject
    private GeronimoJwtAuthConfig config;

    @Inject
    private KidMapper kidMapper;

    @Inject
    private DateValidator dateValidator;

    @Inject
    private SignatureValidator signatureValidator;

    @Inject
    private GeronimoJwtAuthExtension extension;

    private JsonReaderFactory readerFactory;

    private String defaultKid;
    private String defaultAlg;
    private String defaultTyp;
    private boolean validateTyp;

    @PostConstruct
    private void init() {
        readerFactory = Json.createReaderFactory(emptyMap());
        defaultKid = config.read("jwt.header.kid.default", null);
        defaultAlg = config.read("jwt.header.alg.default", "RS256");
        defaultTyp = config.read("jwt.header.typ.default", "JWT");
        validateTyp = Boolean.parseBoolean(config.read("jwt.header.typ.validate", "true"));
    }

    public JsonWebToken parse(final String jwt) {
        final int firstDot = jwt.indexOf('.');
        if (firstDot < 0) {
            throw new JwtException("JWT is not valid", HttpURLConnection.HTTP_BAD_REQUEST);
        }
        final int secondDot = jwt.indexOf('.', firstDot + 1);
        if (secondDot < 0 || jwt.indexOf('.', secondDot + 1) > 0 || jwt.length() <= secondDot) {
            throw new JwtException("JWT is not valid", HttpURLConnection.HTTP_BAD_REQUEST);
        }

        final String rawHeader = jwt.substring(0, firstDot);
        final JsonObject header = loadJson(rawHeader);
        if (validateTyp && !getAttribute(header, "typ", defaultTyp).equalsIgnoreCase("jwt")) {
            throw new JwtException("Invalid typ", HttpURLConnection.HTTP_UNAUTHORIZED);
        }

        final JsonObject payload = loadJson(jwt.substring(firstDot + 1, secondDot));
        dateValidator.checkInterval(payload);

        final String alg = getAttribute(header, "alg", defaultAlg);
        final String kid = getAttribute(header, "kid", defaultKid);
        final Collection<String> issuers = kidMapper.loadIssuers(kid);
        if (!issuers.isEmpty() && issuers.stream().noneMatch(it -> it.equals(payload.getString(Claims.iss.name())))) {
            throw new JwtException("Invalid issuer", HttpURLConnection.HTTP_UNAUTHORIZED);
        }
        signatureValidator.verifySignature(alg, kidMapper.loadKey(kid), jwt.substring(0, secondDot), jwt.substring(secondDot + 1));

        return createToken(jwt, payload);
    }

    public GeronimoJsonWebToken createToken(final String jwt, final JsonObject payload) {
        return new GeronimoJsonWebToken(jwt, payload);
    }

    private String getAttribute(final JsonObject payload, final String key, final String def) {
        final JsonString json = payload.getJsonString(key);
        final String value = json != null ? json.getString() : def;
        if (value == null) {
            throw new JwtException("No " + key + " in JWT", HttpURLConnection.HTTP_UNAUTHORIZED);
        }
        return value;
    }

    private JsonObject loadJson(final String src) {
        return readerFactory.createReader(new ByteArrayInputStream(Base64.getUrlDecoder().decode(src))).readObject();
    }
}
