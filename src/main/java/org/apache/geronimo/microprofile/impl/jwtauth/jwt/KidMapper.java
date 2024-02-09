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

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.apache.geronimo.microprofile.impl.jwtauth.io.PropertiesLoader;
import org.eclipse.microprofile.jwt.config.Names;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import javax.json.JsonValue;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyMap;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

@ApplicationScoped
public class KidMapper {
    @Inject
    private GeronimoJwtAuthConfig config;

    private final ConcurrentMap<String, String> keyMapping = new ConcurrentHashMap<>();
    private final Map<String, Collection<String>> issuerMapping = new HashMap<>();
    private String defaultKey;
    private String jwksUrl;
    private Set<String> defaultIssuers;
    private JsonReaderFactory readerFactory;
    private CompletableFuture<List<JWK>> jwkSetRequest;

    @PostConstruct
    private void init() {
        ofNullable(config.read("kids.key.mapping", null))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(PropertiesLoader::load)
                .ifPresent(props -> props.stringPropertyNames()
                        .forEach(k -> keyMapping.put(k, loadKey(props.getProperty(k)))));
        ofNullable(config.read("kids.issuer.mapping", null))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(PropertiesLoader::load)
                .ifPresent(props -> props.stringPropertyNames()
                        .forEach(k -> {
                            issuerMapping.put(k, Stream.of(props.getProperty(k).split(","))
                                                       .map(String::trim)
                                                       .filter(s -> !s.isEmpty())
                                                       .collect(Collectors.toSet()));
                        }));
        defaultIssuers = ofNullable(config.read("org.eclipse.microprofile.authentication.JWT.issuers", null))
                                .map(s -> Stream.of(s.split(","))
                                    .map(String::trim)
                                    .filter(it -> !it.isEmpty())
                                    .collect(Collectors.toSet()))
                                .orElseGet(HashSet::new);
        ofNullable(config.read("issuer.default", config.read(Names.ISSUER, null))).ifPresent(defaultIssuers::add);
        jwksUrl = config.read("mp.jwt.verify.publickey.location", null);
        ofNullable(jwksUrl).ifPresent(url -> {
            HttpClient httpClient = HttpClient.newBuilder().build();
            HttpRequest request = HttpRequest.newBuilder().GET().uri(URI.create(jwksUrl)).header("Accept", "application/json").build();
            jwkSetRequest =  httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenApply(this::parseKeys);
        });
        defaultKey = config.read("public-key.default", config.read(Names.VERIFIER_PUBLIC_KEY, null));
        readerFactory = Json.createReaderFactory(emptyMap());
    }

    public String loadKey(final String property) {
        String value = keyMapping.get(property);
        if (value == null) {
            value = tryLoad(property);
            if (value != null && !property.equals(value) /* else we can leak easily*/) {
                keyMapping.putIfAbsent(property, value);
            } else if (defaultKey != null) {
                value = defaultKey;
            }
        }
        return value;
    }

    public Collection<String> loadIssuers(final String property) {
        return issuerMapping.getOrDefault(property, defaultIssuers);
    }

    private String tryLoad(final String value) {
        // try external file
        final File file = new File(value);
        if (file.exists()) {
            try {
                return Files.readAllLines(file.toPath()).stream().collect(joining("\n"));
            } catch (final IOException e) {
                throw new IllegalArgumentException(e);
            }
        }

        // if not found try classpath resource
        try (final InputStream stream = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream(value)) {
            if (stream != null) {
                return new BufferedReader(new InputStreamReader(stream)).lines().collect(joining("\n"));
            }
        } catch (final IOException e) {
            throw new IllegalArgumentException(e);
        }

        // load jwks via url
        if (jwksUrl != null) {
            try {
                List<JWK> jwks = jwkSetRequest.get();
                jwks.forEach(jwk -> keyMapping.put(jwk.getKid(), jwk.toPemKey()));
                String key = keyMapping.get(value);
                if (key != null) {
                    return key;
                }
            } catch (InterruptedException | ExecutionException e) {
                // loading of jwks failed
            }
        }
        return value;
    }

    private List<JWK> parseKeys(HttpResponse<String> keyResponse) {
        JsonReader jwksReader = readerFactory.createReader(new StringReader(keyResponse.body()));
        JsonObject keySet = jwksReader.readObject();
        JsonArray keys = keySet.getJsonArray("keys");
        return keys.stream()
                .map(JsonValue::asJsonObject)
                .map(JWK::new)
                .filter(it -> it.getUse() == null || "sig".equals(it.getUse()))
                .collect(toList());
    }

}
