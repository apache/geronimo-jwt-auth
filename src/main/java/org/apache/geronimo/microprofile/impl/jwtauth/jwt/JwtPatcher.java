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

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonPatch;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import java.io.StringReader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Collections.emptyMap;
import static java.util.Optional.ofNullable;

@ApplicationScoped
public class JwtPatcher {
    @Inject
    private GeronimoJwtAuthConfig config;

    private JsonReaderFactory readerFactory;
    private JsonPatch defaultPatch;
    private final ConcurrentMap<String, JsonPatch> patches = new ConcurrentHashMap<>();

    @PostConstruct
    private void init() {
        readerFactory = Json.createReaderFactory(emptyMap());
        defaultPatch = ofNullable(config.read("jwt.header.jwt.payload.patch.default", null))
                .map(it -> {
                    try (final JsonReader reader = readerFactory.createReader(new StringReader(it))) {
                        return reader.readArray();
                    }
                })
                .map(Json::createPatch)
                .orElse(null);
        ofNullable(config.read("jwt.payload.patch.mapping", null))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(PropertiesLoader::load)
                .ifPresent(props -> props.stringPropertyNames().forEach(k -> {
                    final String patch = props.getProperty(k);
                    try (final JsonReader reader = readerFactory.createReader(new StringReader(patch))) {
                        patches.put(k, Json.createPatch(reader.readArray()));
                    }
                }));
    }

    public JsonObject patch(final String kid, final JsonObject raw) {
        final JsonPatch patch = getPatch(kid);
        if (patch == null) {
            return raw;
        }
        return patch.apply(raw);
    }

    protected /*can be overriden to be lazy*/ JsonPatch getPatch(final String kid) {
        if (kid == null) {
            return defaultPatch;
        }
        return kid == null ? defaultPatch : patches.get(kid);
    }
}
