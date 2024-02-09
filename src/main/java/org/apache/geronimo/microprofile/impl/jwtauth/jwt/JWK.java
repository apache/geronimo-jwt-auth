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
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.Base64.Decoder;

import javax.json.JsonObject;

import static java.security.KeyFactory.getInstance;
import static java.util.Optional.*;

public class JWK {

    private String kid;
    private String kty;
    private String n;
    private String e;
    private String x;
    private String y;
    private String crv;
    private String use;

    public JWK(JsonObject jsonObject) {
        kid = jsonObject.getString("kid");
        kty = jsonObject.getString("kty");
        x = jsonObject.getString("x");
        y = jsonObject.getString("y");
        crv = jsonObject.getString("crv");
        n = jsonObject.getString("n");
        e = jsonObject.getString("e");
        use = jsonObject.getString("use", null);
    }

    public String getKid() {
        return kid;
    }

    public String getUse() {
        return use;
    }


	public String toPemKey() {
        PublicKey publicKey = toPublicKey();
        String base64PublicKey = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKey.getEncoded());
        String result = "-----BEGIN PUBLIC KEY-----" + base64PublicKey + "-----END PUBLIC KEY-----";
        return result.replace("\n", "");
	}

    public PublicKey toPublicKey() {
        if ("RSA".equals(kty)) {
            return toRSAPublicKey();
        } else if("EC".equals(kty)) {
            return toECPublicKey();
        } else {
            throw new IllegalStateException("Unsupported kty. Only RSA and EC are supported.");
        }
    }

	private PublicKey toRSAPublicKey() {
        Decoder decoder = Base64.getUrlDecoder();
        BigInteger modulus = ofNullable(n).map(mod -> new BigInteger(1, decoder.decode(mod))).orElseThrow(() -> new IllegalStateException("n must be set for RSA keys."));
        BigInteger exponent = ofNullable(e).map(exp -> new BigInteger(1, decoder.decode(exp))).orElseThrow(() -> new IllegalStateException("e must be set for RSA keys."));
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        try {
            KeyFactory factory = getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    private PublicKey toECPublicKey() {
        Decoder decoder = Base64.getUrlDecoder();
        BigInteger pointX = ofNullable(x).map(x -> new BigInteger(1, decoder.decode(x))).orElseThrow(() -> new IllegalStateException("x must be set for EC keys."));
        BigInteger pointY = ofNullable(y).map(y -> new BigInteger(1, decoder.decode(y))).orElseThrow(() -> new IllegalStateException("y must be set for EC keys."));
        ECPoint pubPoint = new ECPoint(pointX, pointY);
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(ofNullable(crv).map(JWK::mapCrv).map(ECGenParameterSpec::new).orElseThrow(() -> new IllegalStateException("crv must be set for EC keys.")));
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            return getInstance("EC").generatePublic(new ECPublicKeySpec(pubPoint, ecParameters));
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String mapCrv(String crv) {
        if (crv.endsWith("256")) {
           return "secp256r1";
        } else if (crv.endsWith("384")) {
            return "secp384r1";
        } else {
            return "secp521r1";
        }
    }
}
