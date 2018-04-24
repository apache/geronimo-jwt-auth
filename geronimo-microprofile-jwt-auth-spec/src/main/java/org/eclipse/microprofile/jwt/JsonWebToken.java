/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.eclipse.microprofile.jwt;

import java.security.Principal;
import java.util.Optional;
import java.util.Set;

/**
 * Principal used by JWT-Auth specification. It predefines a set
 * of claims.
 */
public interface JsonWebToken extends Principal {

    @Override
    String getName();

    Set<String> getClaimNames();

    <T> T getClaim(String claimName);

    default String getRawToken() {
        return getClaim(Claims.raw_token.name());
    }

    default String getIssuer() {
        return getClaim(Claims.iss.name());
    }

    default Set<String> getAudience() {
        return getClaim(Claims.aud.name());
    }

    default String getSubject() {
        return getClaim(Claims.sub.name());
    }

    default String getTokenID() {
        return getClaim(Claims.jti.name());
    }

    default long getExpirationTime() {
        return getClaim(Claims.exp.name());
    }

    default long getIssuedAtTime() {
        return getClaim(Claims.iat.name());
    }

    default Set<String> getGroups() {
        return getClaim(Claims.groups.name());
    }

    default boolean containsClaim(String claimName) {
        return claim(claimName).isPresent();
    }

    default <T> Optional<T> claim(String claimName) {
        return Optional.ofNullable(getClaim(claimName));
    }
}
