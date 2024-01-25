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
import java.net.URL;
import java.nio.file.Files;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.CreationException;
import javax.inject.Inject;

import org.apache.geronimo.microprofile.impl.jwtauth.config.GeronimoJwtAuthConfig;
import org.apache.geronimo.microprofile.impl.jwtauth.io.PropertiesLoader;
import org.eclipse.microprofile.jwt.config.Names;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;

@ApplicationScoped
public class KidMapper {

	@Inject
	GeronimoJwtAuthConfig config;

	private final ConcurrentMap<String, String> keyMapping = new ConcurrentHashMap<>();

	private final Map<String, Collection<String>> issuerMapping = new HashMap<>();

	private static final String LINE_BREAK = "\n";

	private String defaultKey;

	private String jwksUrl;

	private Set<String> defaultIssuers;

	@PostConstruct
	void init() {
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
		jwksUrl = config.read("verify.publickey.location", null);
		ofNullable(config.read("issuer.default", config.read(Names.ISSUER, null))).ifPresent(defaultIssuers::add);
		defaultKey = config.read("public-key.default", config.read(Names.VERIFIER_PUBLIC_KEY, null));
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
			JWKSet publicKeys = loadJwkSet(jwksUrl);
			for (JWK jsonWebKey : publicKeys.getKeys()) {
				String pemKey = convertJwkToPemKey(jsonWebKey);
				String keyId = jsonWebKey.getKeyID();
				keyMapping.put(keyId, pemKey);
			}
			return keyMapping.get(value);
		}
		return value;
	}

	private JWKSet loadJwkSet(String url) {
		final int httpReadTimeoutMs = 5_000;
		final int httpSizeLimitBytes = 100_000_000;
		final int httpConnectTimeoutMs = 5_000;
		try {
			URL jwks = new URL(url);
			return JWKSet.load(jwks, httpConnectTimeoutMs, httpReadTimeoutMs, httpSizeLimitBytes);
		} catch (Exception e) {
			throw new CreationException(e);
		}
	}

	private String convertJwkToPemKey(JWK jwk) {
		if (isSupportedKeyType(jwk.getKeyType())) {
			throw new IllegalArgumentException("Unsupported key type. Only RSA keys are allowed.");
		}
		PublicKey publicKey = null;
		try {
			publicKey = jwk.toRSAKey().toPublicKey();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		String base64PublicKey = Base64.getMimeEncoder(64, LINE_BREAK.getBytes()).encodeToString(publicKey.getEncoded());
		String result = "-----BEGIN PUBLIC KEY-----" + base64PublicKey + "-----END PUBLIC KEY-----";
		return result.replace(LINE_BREAK, "");
	}

	private boolean isSupportedKeyType(KeyType keyType) {
		return keyType != KeyType.RSA;
	}
}
