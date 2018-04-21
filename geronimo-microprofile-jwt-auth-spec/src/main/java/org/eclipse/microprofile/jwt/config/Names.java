package org.eclipse.microprofile.jwt.config;

public class Names {
    public final static String VERIFIER_PUBLIC_KEY = "org.eclipse.microprofile.authentication.JWT.verifierPublicKey";

    public final static String ISSUER = "org.eclipse.microprofile.authentication.JWT.issuer";

    public final static String ISSUERS = "org.eclipse.microprofile.authentication.JWT.issuers";

    public final static String CLOCK_SKEW = "org.eclipse.microprofile.authentication.JWT.clockSkew";

    public final static String VERIFIER_JWKS_URI = "org.eclipse.microprofile.authentication.JWT.VERIFIER_JWKS_URI";

    public final static String VERIFIER_JWKS_REFRESH_INTERVAL = "org.eclipse.microprofile.authentication.JWT.VERIFIER_JWKS_REFRESH_INTERVAL";

    private Names() {
        throw new AssertionError("don't call me");
    }
}
