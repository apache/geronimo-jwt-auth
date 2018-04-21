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
import java.util.Base64;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReaderFactory;

import org.eclipse.microprofile.jwt.JsonWebToken;

@ApplicationScoped
public class JwtService {
    private JsonReaderFactory readerFactory;

    @PostConstruct
    private void init() {
        readerFactory = Json.createReaderFactory(emptyMap());
    }

    public JsonWebToken parse(final String jwt) {
        // TODO
        final String[] split = jwt.split("\\.");
        if (split.length != 3) {
            // fail
        }
        // sign, date validation etc but without lib please, use GeronimoJwtAuthConfig to read how in postconstruct

        final byte[] token = Base64.getUrlDecoder().decode(split[1]);
        final JsonObject json = readerFactory.createReader(new ByteArrayInputStream(token)).readObject();
        return new GeronimoJsonWebToken(jwt, json);
    }
}
