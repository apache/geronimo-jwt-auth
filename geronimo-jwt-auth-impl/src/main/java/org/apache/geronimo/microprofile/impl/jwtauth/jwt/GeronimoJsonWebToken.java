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

import static java.util.stream.Collectors.toSet;

import java.util.Set;
import java.util.stream.Stream;

import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

class GeronimoJsonWebToken implements JsonWebToken {
    private final JsonObject delegate;
    private final String raw;

    GeronimoJsonWebToken(final String raw, final JsonObject delegate) {
        this.raw = raw;
        this.delegate = delegate;
    }

    @Override
    public String getName() {
        return getClaim(Claims.upn.name());
    }

    @Override
    public Set<String> getClaimNames() {
        return delegate.keySet();
    }

    @Override
    public <T> T getClaim(final String claimName) {
        try {
            final Claims claim = Claims.valueOf(claimName);
            if (claim == Claims.raw_token) {
                return (T) raw;
            }
            if (claim.getType() == String.class) {
                return (T) delegate.getString(claimName);
            }
            if (claim.getType() == Long.class) {
                return (T) Long.valueOf(delegate.getJsonNumber(claimName).longValue());
            }
            if (claim.getType() == JsonObject.class) {
                return (T) delegate.getJsonObject(claimName);
            }
            if (claim.getType() == Set.class) {
                final JsonValue jsonValue = delegate.get(claimName);
                if (jsonValue == null) {
                    return null;
                }
                if (jsonValue.getValueType() == JsonValue.ValueType.ARRAY) {
                    return (T) JsonArray.class.cast(jsonValue).stream()
                            .map(this::toString)
                            .collect(toSet());
                }
                if (jsonValue.getValueType() == JsonValue.ValueType.STRING) {
                    return (T) Stream.of(JsonString.class.cast(jsonValue).getString().split(","))
                            .collect(toSet());
                }
                return (T) jsonValue;
            }
            return (T) delegate.get(claimName);
        } catch (final IllegalArgumentException iae) {
            return (T) delegate.get(claimName);
        }
    }

    private String toString(final Object value) {
        if (JsonString.class.isInstance(value)) {
            return JsonString.class.cast(value).getString();
        }
        if (JsonNumber.class.isInstance(value)) {
            return String.valueOf(JsonNumber.class.cast(value).doubleValue());
        }
        return value.toString();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }
}
