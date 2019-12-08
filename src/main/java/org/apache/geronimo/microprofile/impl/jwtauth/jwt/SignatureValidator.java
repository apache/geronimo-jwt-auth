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

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.geronimo.microprofile.impl.jwtauth.JwtException;
import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;

@ApplicationScoped
public class SignatureValidator {
    @Inject
    private GeronimoJwtAuthConfig config;

    private Set<String> supportedAlgorithms;
    private String jcaProvider;
    private boolean useCache;
    private final ConcurrentMap<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();

    @PostConstruct
    private void init() {
        useCache = Boolean.parseBoolean(config.read("public-key.cache.active", "true"));
        supportedAlgorithms = Stream.of(config.read("header.alg.supported", "RS256").split(","))
                .map(String::trim)
                .map(s -> s.toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(toSet());
        jcaProvider = config.read("jca.provider", null);
    }

    public void verifySignature(final String alg, final String key, final String signingString, final String expected) {
        final String normalizedAlg = alg.toLowerCase(Locale.ROOT);
        if (!supportedAlgorithms.contains(normalizedAlg)) {
            throw new JwtException("Unsupported algorithm", HttpURLConnection.HTTP_UNAUTHORIZED);
        }
        switch (normalizedAlg) {
            case "rs256":
                verifySignature(toPublicKey(key, "RSA"), signingString, expected, "SHA256withRSA");
                break;
            case "rs384":
                verifySignature(toPublicKey(key, "RSA"), signingString, expected, "SHA384withRSA");
                break;
            case "rs512":
                verifySignature(toPublicKey(key, "RSA"), signingString, expected, "SHA512withRSA");
                break;
            case "hs256":
                verifyMac(toSecretKey(key, "HmacSHA256"), signingString, expected);
                break;
            case "hs384":
                verifyMac(toSecretKey(key, "HmacSHA384"), signingString, expected);
                break;
            case "hs512":
                verifyMac(toSecretKey(key, "HmacSHA512"), signingString, expected);
                break;
            case "es256":
                verifySignature(toPublicKey(key, "EC"), signingString, expected, "SHA256withECDSA");
                break;
            case "es384":
                verifySignature(toPublicKey(key, "EC"), signingString, expected, "SHA384withECDSA");
                break;
            case "es512":
                verifySignature(toPublicKey(key, "EC"), signingString, expected, "SHA512withECDSA");
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + normalizedAlg);
        }
    }

    private SecretKey toSecretKey(final String key, final String algo) {
        return new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algo);
    }

    private PublicKey toPublicKey(final String key, final String algo) {
        PublicKey publicKey = useCache ? publicKeyCache.get(key) : null;
        if (publicKey == null) {
            final byte[] decoded = Base64.getDecoder().decode(key
                    .replace("-----BEGIN RSA KEY-----", "")
                    .replace("-----END RSA KEY-----", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                    .replace("-----END RSA PUBLIC KEY-----", "")
                    .replace("\n", "")
                    .trim());
            try {
                switch (algo) {
                    case "RSA": {
                        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
                        final KeyFactory keyFactory = KeyFactory.getInstance(algo);
                        publicKey = keyFactory.generatePublic(keySpec);
                        if (useCache) {
                            publicKeyCache.putIfAbsent(key, publicKey);
                        }
                        break;
                    }
                    case "EC": // TODO
                    default:
                        throw new JwtException("Invalid signing", HttpURLConnection.HTTP_UNAUTHORIZED);
                }
            } catch (final Exception e) {
                throw new JwtException("Invalid signing", HttpURLConnection.HTTP_UNAUTHORIZED);
            }
        }
        return publicKey;
    }

    private void verifyMac(final SecretKey key, final String signingString, final String expected) {
        try {
            final Mac signature = jcaProvider == null ?
                    Mac.getInstance(key.getAlgorithm()) :
                    Mac.getInstance(key.getAlgorithm(), jcaProvider);
            signature.init(key);
            signature.update(signingString.getBytes(StandardCharsets.UTF_8));
            if (!Arrays.equals(signature.doFinal(), Base64.getUrlDecoder().decode(expected))) {
                invalidSignature();
            }
        } catch (final Exception e) {
            invalidSignature();
        }
    }

    private void verifySignature(final PublicKey publicKey, final String signingString, final String expected,
                                 final String algo) {
        try {
            final Signature signature = jcaProvider == null ?
                    Signature.getInstance(algo) :
                    Signature.getInstance(algo, jcaProvider);
            signature.initVerify(publicKey);
            signature.update(signingString.getBytes(StandardCharsets.UTF_8));
            if (!signature.verify(Base64.getUrlDecoder().decode(expected))) {
                invalidSignature();
            }
        } catch (final Exception e) {
            invalidSignature();
        }
    }

    private void invalidSignature() {
        throw new JwtException("Invalid signature", HttpURLConnection.HTTP_UNAUTHORIZED);
    }
}
