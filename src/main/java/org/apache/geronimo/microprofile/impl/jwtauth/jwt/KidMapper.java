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
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.joining;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.apache.geronimo.microprofile.impl.jwtauth.io.PropertiesLoader;
import org.eclipse.microprofile.jwt.config.Names;

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
            loadJwkSet(jwksUrl).forEach(jwk -> keyMapping.put(jwk.getKid(), jwk.toPemKey()));
            String key = keyMapping.get(value);
            if (key != null) {
                return key;
            }
        }
        return value;
    }

    private List<JWK> loadJwkSet(String url) {
        try {
            URL jwks = new URL(url);
            try (InputStream connection = jwks.openStream(); JsonReader jwksReader = readerFactory.createReader(connection)) {
                JsonObject keySet = jwksReader.readObject();
                JsonArray keys = keySet.getJsonArray("keys");
                List<JWK> parsedKeys = parseKeys(keys);
                return parsedKeys;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private List<JWK> parseKeys(JsonArray keys) {
        List<JWK> parsedKeys = new ArrayList<>(keys.size());
        keys.forEach(key -> {
            JWK jwk = new JWK((JsonObject) key);
            if (isSignatureKey(jwk)) {
                parsedKeys.add(jwk);
            }
        });
        return parsedKeys;
    }

    private boolean isSignatureKey(JWK key) {
        Optional<String> use = key.getUse();
        if (use.isPresent()) {
            return use.get().equals("sig");
        }
        return true;
    }
}
