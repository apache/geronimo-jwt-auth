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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Optional;

import javax.json.JsonObject;

public class JWK {

    private String kid;
    private String kty;
    private String n;
    private String e;
    private String use;

    public JWK(JsonObject jsonObject) {
        kid = jsonObject.getString("kid");
        kty = jsonObject.getString("kty");
        n = jsonObject.getString("n");
        e = jsonObject.getString("e");
        use = jsonObject.getString("use", null);
    }

    public String getKid() {
        return kid;
    }

    public String getKty() {
		return kty;
	}

    public String getN() {
		return n;
    }

    public String getE() {
        return e;
    }

    public Optional<String> getUse() {
        return Optional.ofNullable(use);
    }

	public String toPemKey() {
        PublicKey publicKey = toRSAPublicKey();
        String base64PublicKey = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKey.getEncoded());
        String result = "-----BEGIN PUBLIC KEY-----" + base64PublicKey + "-----END PUBLIC KEY-----";
        return result.replace("\n", "");
	}

	public RSAPublicKey toRSAPublicKey() {
        if (!"RSA".equals(kty)) {
            throw new UnsupportedOperationException("Unsupported key type. Only RSA keys are allowed.");
        }

        Decoder decoder = Base64.getUrlDecoder();
        BigInteger modulus = new BigInteger(1, decoder.decode(n));
        BigInteger exponent = new BigInteger(1, decoder.decode(e));
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey)factory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }
}
