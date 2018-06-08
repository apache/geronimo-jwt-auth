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

import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import javax.security.auth.Subject;

import org.eclipse.microprofile.jwt.JsonWebToken;

public class ContextualJsonWebToken implements JsonWebToken {
    private final Supplier<JsonWebToken> provider;

    public ContextualJsonWebToken(final Supplier<JsonWebToken> provider) {
        this.provider = provider;
    }

    @Override
    public String getName() {
        return provider.get().getName();
    }

    @Override
    public String getRawToken() {
        return provider.get().getRawToken();
    }

    @Override
    public String getIssuer() {
        return provider.get().getIssuer();
    }

    @Override
    public Set<String> getAudience() {
        return provider.get().getAudience();
    }

    @Override
    public String getSubject() {
        return provider.get().getSubject();
    }

    @Override
    public String getTokenID() {
        return provider.get().getTokenID();
    }

    @Override
    public long getExpirationTime() {
        return provider.get().getExpirationTime();
    }

    @Override
    public long getIssuedAtTime() {
        return provider.get().getIssuedAtTime();
    }

    @Override
    public Set<String> getGroups() {
        return provider.get().getGroups();
    }

    @Override
    public Set<String> getClaimNames() {
        return provider.get().getClaimNames();
    }

    @Override
    public boolean containsClaim(String claimName) {
        return provider.get().containsClaim(claimName);
    }

    @Override
    public <T> T getClaim(final String claimName) {
        return provider.get().getClaim(claimName);
    }

    @Override
    public <T> Optional<T> claim(String claimName) {
        return provider.get().claim(claimName);
    }

    @Override
    public boolean implies(final Subject subject) {
        return provider.get().implies(subject);
    }

    @Override
    public String toString() {
        return provider.get().toString();
    }
}
