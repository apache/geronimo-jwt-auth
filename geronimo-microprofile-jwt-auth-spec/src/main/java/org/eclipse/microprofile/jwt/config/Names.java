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
package org.eclipse.microprofile.jwt.config;

/**
 * Some constants for the configuration.
 */
public class Names {
    /**
     * Default public key used to verify the JWT.
     * Format must be a PEM base64 encoded RSA key.
     */
    public final static String VERIFIER_PUBLIC_KEY = "org.eclipse.microprofile.authentication.JWT.verifierPublicKey";

    /**
     * Default issuer used to verify the JWT.
     */
    public final static String ISSUER = "org.eclipse.microprofile.authentication.JWT.issuer";

    /**
     * List of supported issuers.
     */
    public final static String ISSUERS = "org.eclipse.microprofile.authentication.JWT.issuers";

    /**
     * The date tokerance for the JWT validation (exp/iat) in seconds.
     */
    public final static String CLOCK_SKEW = "org.eclipse.microprofile.authentication.JWT.clockSkew";

    /**
     * URI the verifier can call to get a JSON Web Key Set.
     */
    public final static String VERIFIER_JWKS_URI = "org.eclipse.microprofile.authentication.JWT.VERIFIER_JWKS_URI";

    /**
     * Cache for previous key content if used.
     */
    public final static String VERIFIER_JWKS_REFRESH_INTERVAL = "org.eclipse.microprofile.authentication.JWT.VERIFIER_JWKS_REFRESH_INTERVAL";

    private Names() {
        // no-op
    }
}
