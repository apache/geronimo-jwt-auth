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
import static java.util.stream.Collectors.joining;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.apache.geronimo.microprofile.impl.jwtauth.io.PropertiesLoader;

@ApplicationScoped
public class KidMapper {
    @Inject
    private GeronimoJwtAuthConfig config;

    private final ConcurrentMap<String, String> keyMapping = new ConcurrentHashMap<>();
    private final Map<String, String> issuerMapping = new HashMap<>();
    private String defaultIssuer;

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
                        .forEach(k -> issuerMapping.put(k, props.getProperty(k))));
        defaultIssuer = config.read("issuer.default", null);
    }

    String loadKey(final String property) {
        String value = keyMapping.get(property);
        if (value == null) {
            value = tryLoad(property);
            if (value != null && !property.equals(value) /* else we can leak easily*/) {
                keyMapping.putIfAbsent(property, value);
            }
        }
        return value;
    }

    String loadIssuer(final String property) {
        return issuerMapping.getOrDefault(property, defaultIssuer);
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

        // else direct value
        return value;
    }
}
