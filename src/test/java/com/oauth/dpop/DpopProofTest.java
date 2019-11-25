package com.oauth.dpop;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.oauth.dpop.exception.DpopInvalidFormatException;
import com.oauth.dpop.exception.DpopInvalidSignatureException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.junit.MatcherAssert.assertThat;

public class DpopProofTest {

    private static final String DPOP_RFC = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik"+
            "VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR"+
            "nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE"+
            "QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj"+
            "oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia"+
            "WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg"+
            "4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";

    private static final String VALID_HTM = "POST";
    private static final String INVALID_HTM = "NOTAHTM";
    private static final String VALID_HTU = "https://myresourceserver.com/resource/abc";
    private static final String DPOP_JWT_TYPE = "dpop+jwt";

    private String jti;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() {
        this.jti = UUID.randomUUID().toString();
    }

    @Test
    public void testDpopFromRfcParsing() throws Exception {
        DpopProof dpopProof = DpopProof.parse(DPOP_RFC);
        assertThat(dpopProof.getJti(), is("-BwC3ESc6acc2lTc"));
        assertThat(dpopProof.getAlgorithm(), is("ES256"));
        assertThat(dpopProof.getJwk(), notNullValue());
        assertThat(dpopProof.getHttpMethod(), is("POST"));
        assertThat(dpopProof.getHttpUri(), is("https://server.example.com/token"));
        assertThat(dpopProof.getIssuedAt().getTime(), is(1562262616000L));

        JWK dpopKey = dpopProof.getJwk();
        assertThat(dpopKey.getKeyType(), is(KeyType.EC));
        ECKey ecKey = (ECKey) dpopKey;
        assertThat(ecKey.getX().toString(), is("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"));
        assertThat(ecKey.getY().toString(), is("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"));
        assertThat(ecKey.getCurve(), is(Curve.P_256));
    }

    @Test
    public void testDpopParsingWithCustomJwt() throws Exception {
        Date issuedAt = Calendar.getInstance().getTime();
        String dpopJwt = new DpopGenerator.Builder()
                .withJti(jti)
                .withHtm(VALID_HTM)
                .withHtu(VALID_HTU)
                .withIat(issuedAt)
                .build();

        DpopProof dpopProof = DpopProof.parse(dpopJwt);
        assertThat(dpopProof.getJti(), is(jti));
        assertThat(dpopProof.getHttpMethod(), is(VALID_HTM));
        assertThat(dpopProof.getHttpUri(), is(VALID_HTU));
    }

    @Test
    public void testDPoPInvalidSignatureForJwkInHeader() throws Exception {
        String spoofedDpopProof = getBaseDpop().withBadSignature(true).build();
        expectedException.expect(DpopInvalidSignatureException.class);
        DpopProof.parse(spoofedDpopProof);
    }

    @Test
    public void testDPoPIsSignedByHappyPath() throws Exception {
        ECKey someKey = DpopGenerator.generateEcKey("some-key");
        String dpopProofJwt = getBaseDpop().withECKey(someKey).build();
        assertThat(DpopProof.parse(dpopProofJwt).isSignedBy(someKey), is(true));
    }

    @Test
    public void testDPoPIsSignedByKeyMismatch() throws Exception {
        ECKey badKey = DpopGenerator.generateEcKey("some-key");
        String dpopProofJwt = getBaseDpop().build();
        assertThat(DpopProof.parse(dpopProofJwt).isSignedBy(badKey), is(false));
    }

    @Test
    public void testDPoPNoHtm() throws Exception {
        expectDpopInvalidFormatExceptionForClaim("htm");
        DpopProof.parse(getBaseDpop().withHtm(null).build());
    }

    @Test
    public void testDPoPNoHtu() throws Exception {
        expectDpopInvalidFormatExceptionForClaim("htu");
        DpopProof.parse(getBaseDpop().withHtu(null).build());
    }

    @Test
    public void testDPoPNoJti() throws Exception {
        expectDpopInvalidFormatExceptionForClaim("jti");
        DpopProof.parse(getBaseDpop().withJti(null).build());
    }

    @Test
    public void testDPoPBadType() throws Exception {
        expectedException.expect(DpopInvalidFormatException.class);
        expectedException.expectMessage("Invalid type=foo Expected dpop+jwt");
        DpopProof.parse(getBaseDpop().withType("foo").build());
    }

    @Test
    public void testDPoPNoJwkInHeader() throws Exception {
        expectedException.expect(DpopInvalidFormatException.class);
        expectedException.expectMessage("No JWK specified in header");
        DpopProof.parse(getBaseDpop().withNoKeyInHeader(true).build());
    }

    @Test
    public void testDPoPNoTypeInHeader() throws Exception {
        expectedException.expect(DpopInvalidFormatException.class);
        expectedException.expectMessage("No type specified");
        DpopProof.parse(getBaseDpop().withType(null).build());
    }

    private void expectDpopInvalidFormatExceptionForClaim(String claim) {
        expectedException.expect(DpopInvalidFormatException.class);
        expectedException.expectMessage(claim + " claim not present");
    }

    private DpopGenerator.Builder getBaseDpop() {
        Date issuedAt = Calendar.getInstance().getTime();
        return new DpopGenerator.Builder()
                .withJti(jti)
                .withHtm(VALID_HTM)
                .withHtu(VALID_HTU)
                .withIat(issuedAt);
    }
}
