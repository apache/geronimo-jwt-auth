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
package org.apache.geronimo.microprofile.impl.jwtauth.jaxrs;

import static java.util.Collections.emptyMap;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.json.Json;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;

import org.apache.geronimo.microprofile.impl.jwtauth.JwtException;

@ApplicationScoped
public class ResponseBuilder {
    private JsonBuilderFactory factory;

    @PostConstruct
    private void createBuilderFactory() {
        factory = Json.createBuilderFactory(emptyMap());
    }

    public JsonObject toObject(final JwtException exception) {
        return factory.createObjectBuilder()
                .add("message", exception.getMessage())
                .build();
    }
}
