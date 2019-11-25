package com.oauth.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.Date;

public class DpopGenerator {
    private static final String DPOP_JWT_TYPE = "dpop+jwt";
    private static final String DPOP_KEY_ID = "dpop-test-key";
    private static final String DPOP_BAD_KEY_ID = "dpop-test-invalid-key";

    public static ECKey generateEcKey(String keyId) throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyID(keyId)
                .generate();
    }

    public static class Builder {
        private String type;
        private String jti;
        private String htm;
        private String htu;
        private Date iat;
        private JWK jwk;
        boolean badSignature;
        boolean noKeyInHeader;

        Builder() {
            this.type = DPOP_JWT_TYPE;
        }

        public Builder withType(String type) {
            this.type = type;
            return this;
        }

        public Builder withJti(String jti) {
            this.jti = jti;
            return this;
        }

        public Builder withHtm(String htm) {
            this.htm = htm;
            return this;
        }

        public Builder withHtu(String htu) {
            this.htu = htu;
            return this;
        }

        public Builder withIat(Date issuedAt) {
            this.iat = issuedAt;
            return this;
        }

        public Builder withECKey(ECKey jwk) {
            this.jwk = jwk;
            return this;
        }

        public Builder withBadSignature(boolean badSignature) {
            this.badSignature = true;
            return this;
        }

        public Builder withNoKeyInHeader(boolean noKeyInHeader) {
            this.noKeyInHeader = true;
            return this;
        }

        public String build() throws JOSEException {
            // TODO: Be more flexible with signing options.
            // Right now just using ECDSA for simplicity
            ECKey signingKeyInHeader = null;
            if (jwk != null) {
                signingKeyInHeader = (ECKey) jwk;
            } else {
                signingKeyInHeader = generateEcKey(DPOP_KEY_ID);
            }
            // Used to generate JWTs with a bad signature for tests
            ECKey badJWK = null;
            if (badSignature) {
                badJWK = generateEcKey(DPOP_BAD_KEY_ID);
            }

            JWSSigner signer = badSignature ? new ECDSASigner(badJWK) : new ECDSASigner(signingKeyInHeader);

            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
            claimsSetBuilder = jti != null ? claimsSetBuilder.claim("jti", jti) : claimsSetBuilder;
            claimsSetBuilder = htm != null ? claimsSetBuilder.claim("htm", htm) : claimsSetBuilder;
            claimsSetBuilder = htu != null ? claimsSetBuilder.claim("htu", htu) : claimsSetBuilder;
            claimsSetBuilder = iat != null ? claimsSetBuilder.issueTime(iat) : claimsSetBuilder;


            JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256);
            jwsHeaderBuilder = noKeyInHeader ? jwsHeaderBuilder : jwsHeaderBuilder.jwk(signingKeyInHeader);
            jwsHeaderBuilder = type != null ? jwsHeaderBuilder.type(new JOSEObjectType(type)) : jwsHeaderBuilder;

            SignedJWT signedJWT = new SignedJWT(jwsHeaderBuilder.build(), claimsSetBuilder.build());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        }

    }
}
