package com.oauth.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.oauth.dpop.exception.DpopInvalidFormatException;
import com.oauth.dpop.exception.DpopInvalidSignatureException;

import java.text.ParseException;
import java.util.Date;

public class DpopProof {

    private static final String DPOP_JWT_TYPE = "dpop+jwt";
    private static final String JTI_CLAIM = "jti";
    private static final String HTTP_METHOD_CLAIM = "htm";
    private static final String HTTP_URI_CLAIM = "htu";
    private static final String ISSUED_AT_CLAIM = "iat";

    private final SignedJWT dpopProofJwt;
    private JWK jwk;
    private String jti;
    private String httpMethod;
    private String httpUri;
    private Date issuedAt;
    private String algorithm;

    /**
     * Parse the DPoP proof JWT
     *
     * @param dpopProofJwt
     * @return the parsed DPoP proof JWT
     * @throws ParseException, when the JWT cannot be parsed
     * @throws JOSEException, on errors verifying the signature
     * @throws DpopInvalidFormatException, when format of DPoP is invalid or not RFC compliant
     * @throws DpopInvalidSignatureException, when the DPoP proof is not signed by the JWK in the header
     */
    public static DpopProof parse(String dpopProofJwt) throws ParseException, JOSEException, DpopInvalidFormatException, DpopInvalidSignatureException {
        return new DpopProof(SignedJWT.parse(dpopProofJwt));
    }

    /**
     * Validate if the DPoP Proof JWT is indeed signed by the given key.
     * This can be used to verify if the DPoP proof is not signed by the key
     * bound to the client
     *
     * @param signingKey, the signingKey used to validate the signature on the DPoP proof
     * @return true, if DPoP is signed by key, false otherwise
     * @throws JOSEException on errors verifying the signature
     */
    public boolean isSignedBy(JWK signingKey) throws JOSEException{
        return validateSignature(signingKey);
    }

    public JWK getJwk() {
        return jwk;
    }

    public String getJti() {
        return jti;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getHttpUri() {
        return httpUri;
    }

    public Date getIssuedAt() {
        return issuedAt;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    private DpopProof(SignedJWT dpopProofJwt) throws ParseException, JOSEException, DpopInvalidFormatException, DpopInvalidSignatureException {
        this.dpopProofJwt = dpopProofJwt;
        validateFormat();
        validateSignature();
    }

    private void validateFormat() throws ParseException, DpopInvalidFormatException {
        validateHeader();
        validateAndPopulateClaims();
    }

    private void validateSignature() throws DpopInvalidSignatureException, JOSEException {
        if (!validateSignature(this.jwk)) {
            throw new DpopInvalidSignatureException();
        }
    }

    private boolean validateSignature(JWK signingKey) throws JOSEException {
        // TODO: Make signature validation more robust
        JWSVerifier verifier;
        if (signingKey instanceof ECKey) {
            ECKey ecKey = (ECKey) signingKey;
            verifier = new ECDSAVerifier(ecKey);
        } else if (signingKey instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) signingKey;
            verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
        } else {
            throw new IllegalArgumentException(String.format("Unexpected key type=%s", signingKey.getKeyType().getValue()));
        }
        return dpopProofJwt.verify(verifier);
    }


    private void validateAndPopulateClaims() throws ParseException, DpopInvalidFormatException {
        JWTClaimsSet jwtClaimsSet = dpopProofJwt.getJWTClaimsSet();
        assertClaimsExist(jwtClaimsSet, JTI_CLAIM, HTTP_METHOD_CLAIM, HTTP_URI_CLAIM, ISSUED_AT_CLAIM);
        this.jti = jwtClaimsSet.getStringClaim(JTI_CLAIM);
        this.httpMethod = jwtClaimsSet.getStringClaim(HTTP_METHOD_CLAIM);
        this.httpUri = jwtClaimsSet.getStringClaim(HTTP_URI_CLAIM);
        this.issuedAt = jwtClaimsSet.getIssueTime();
    }

    private void assertClaimsExist(JWTClaimsSet jwtClaimsSet, String... claims) throws DpopInvalidFormatException {
        for (String claim : claims) {
            assertClaimExists(jwtClaimsSet, claim);
        }
    }

    private void assertClaimExists(JWTClaimsSet jwtClaimsSet, String claim) throws DpopInvalidFormatException {
        if (jwtClaimsSet.getClaim(claim) == null) {
            throw new DpopInvalidFormatException(String.format("%s claim not present", claim));
        }
    }

    private void validateHeader() throws DpopInvalidFormatException {
        JWSHeader jwsHeader = dpopProofJwt.getHeader();
        JOSEObjectType objectType = jwsHeader.getType();
        if (objectType == null) {
            throw new DpopInvalidFormatException("No type specified");
        }
        String typ = objectType.getType();
        if (!DPOP_JWT_TYPE.equals(typ)) {
            throw new DpopInvalidFormatException(String.format("Invalid type=%s Expected dpop+jwt", typ));
        }
        this.jwk = jwsHeader.getJWK();
        if (jwk == null) {
            throw new DpopInvalidFormatException("No JWK specified in header");
        }
        JWSAlgorithm jwsAlgorithm = jwsHeader.getAlgorithm();
        if (jwsAlgorithm == null) {
            throw new DpopInvalidFormatException("No JWS algorithm specified in header");
        }
        // TODO: Validate JWS algorithm is accepted by server and algorithm on JWK and JWS match
        this.algorithm = jwsAlgorithm.getName();
    }

}
