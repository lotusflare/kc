/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oidc.grants.ciba.endpoints.request;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.models.CibaConfig;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.TokenManager;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.util.JsonSerialization;
import com.fasterxml.jackson.databind.JsonNode;

import static org.junit.Assert.*;

public class CamaraCibaRequestParserTest {

    private final Map<String, String> attributes = new HashMap<>();
    private final Map<String, Object> sessionAttributes = new HashMap<>();
    private ClientModel client;
    private KeycloakSession session;
    private CibaConfig config;
    private JsonNode verifiedClaims;
    private int verifications;
    private int fetches;
    private String signed;

    @Before
    public void setup() {
        attributes.put(CibaConfig.CAMARA_CIBA_ENABLED, "true");
        attributes.put(CibaConfig.CIBA_BACKCHANNEL_AUTH_REQUEST_SIGNING_ALG, "RS256");
        client = stub(ClientModel.class, (p, m, a) -> {
            switch (m.getName()) {
                case "getAttribute": return attributes.get(a[0]);
                case "setAttribute": attributes.put((String) a[0], (String) a[1]); return null;
                case "getRootUrl": return "https://client.example";
                default: throw new AssertionError(m.getName());
            }
        });
        RealmModel realm = stub(RealmModel.class, (p, m, a) -> {
            if (m.getName().equals("getAttribute")) return a.length == 2 ? a[1] : null;
            throw new AssertionError(m.getName());
        });
        config = new CibaConfig(realm);
        KeycloakContext context = stub(KeycloakContext.class, (p, m, a) -> null);
        SignatureProvider signature = stub(SignatureProvider.class, (p, m, a) -> {
            if (m.getName().equals("isAsymmetricAlgorithm")) return true;
            throw new AssertionError(m.getName());
        });
        TokenManager tokens = stub(TokenManager.class, (p, m, a) -> {
            if (m.getName().equals("decodeClientJWT")) {
                verifications++;
                assertEquals(signed, a[0]);
                assertSame(client, a[1]);
                return verifiedClaims;
            }
            throw new AssertionError(m.getName());
        });
        HttpClientProvider http = stub(HttpClientProvider.class, (p, m, a) -> {
            if (m.getName().equals("getString")) {
                fetches++;
                assertEquals("https://client.example/request.jwt", a[0]);
                return signed;
            }
            throw new AssertionError(m.getName());
        });
        session = stub(KeycloakSession.class, (p, m, a) -> {
            switch (m.getName()) {
                case "getContext": return context;
                case "tokens": return tokens;
                case "getProvider": return a[0] == SignatureProvider.class ? signature : http;
                case "setAttribute": sessionAttributes.put((String) a[0], a[1]); return null;
                default: throw new AssertionError(m.getName());
            }
        });
    }

    @Test
    public void formIgnoresFieldsBeforeIntegerConversionAndKeepsOtherFields() {
        MultivaluedMap<String, String> form = form();
        form.putSingle("requested_expiry", "not-an-integer");
        form.add("binding_message", "duplicate ignored value");
        BackchannelAuthenticationEndpointRequest result = parse(form);
        assertIgnored(result);
        assertEquals("openid", result.getScope());
        assertEquals("user_0001", result.getLoginHint());
        assertEquals("notification", result.getClientNotificationToken());
        assertEquals("mobile", result.getAdditionalReqParams().get("user_device"));
        assertNull(result.getInvalidRequestMessage());
        assertEquals("not-an-integer", form.getFirst("requested_expiry"));
    }

    @Test
    public void defaultAndDisabledClientsKeepStockFields() {
        for (String setting : new String[] {null, "false"}) {
            attributes.put(CibaConfig.CAMARA_CIBA_ENABLED, setting);
            BackchannelAuthenticationEndpointRequest result = parse(form());
            assertEquals("a message with spaces", result.getBindingMessage());
            assertEquals("1234", result.getUserCode());
            assertEquals("acr1", result.getAcr());
            assertEquals(Integer.valueOf(60), result.getRequestedExpiry());
        }
    }

    @Test
    public void disabledClientStillRejectsNonNumericExpiry() {
        attributes.put(CibaConfig.CAMARA_CIBA_ENABLED, "false");
        MultivaluedMap<String, String> form = form();
        form.putSingle("requested_expiry", "not-an-integer");
        assertThrows(ErrorResponseException.class, () -> parse(form));
    }

    @Test
    public void otherIntegerValidationStillRuns() {
        MultivaluedMap<String, String> form = form();
        form.putSingle("max_age", "not-an-integer");
        assertThrows(ErrorResponseException.class, () -> parse(form));
    }

    @Test
    public void signedRequestIsVerifiedAndClaimsStayAvailableToPolicies() throws Exception {
        prepareSignedClaims();
        MultivaluedMap<String, String> form = form();
        form.putSingle("request", signed);
        BackchannelAuthenticationEndpointRequest result = parse(form);
        assertIgnored(result);
        assertEquals("openid signed", result.getScope());
        assertEquals("signed_user", result.getLoginHint());
        assertEquals(1, verifications);
        assertSame(verifiedClaims, sessionAttributes.get(BackchannelAuthenticationEndpointRequestParser.CIBA_SIGNED_AUTHENTICATION_REQUEST));
        assertEquals("not-an-integer", verifiedClaims.get("requested_expiry").asText());
        assertEquals(signed, form.getFirst("request"));
    }

    @Test
    public void requestUriUsesRegisteredUriAndOriginalVerification() throws Exception {
        prepareSignedClaims();
        OIDCAdvancedConfigWrapper.fromClientModel(client).setRequestUris(java.util.List.of("https://client.example/request.jwt"));
        MultivaluedMap<String, String> form = form();
        form.putSingle("request_uri", "https://client.example/request.jwt");
        assertIgnored(parse(form));
        assertEquals(1, fetches);
        assertEquals(1, verifications);
    }

    @Test
    public void unregisteredRequestUriIsRejectedBeforeFetch() throws Exception {
        prepareSignedClaims();
        OIDCAdvancedConfigWrapper.fromClientModel(client).setRequestUris(java.util.List.of("https://client.example/other.jwt"));
        MultivaluedMap<String, String> form = form();
        form.putSingle("request_uri", "https://client.example/request.jwt");
        assertThrows(ErrorResponseException.class, () -> parse(form));
        assertEquals(0, fetches);
    }

    @Test
    public void invalidSignatureStillRejectsRequest() throws Exception {
        prepareSignedClaims();
        verifiedClaims = null;
        MultivaluedMap<String, String> form = form();
        form.putSingle("request", signed);
        assertThrows(ErrorResponseException.class, () -> parse(form));
        assertEquals(1, verifications);
    }

    @Test
    public void signingAlgorithmMismatchStillRejectsRequest() throws Exception {
        prepareSignedClaims();
        attributes.put(CibaConfig.CIBA_BACKCHANNEL_AUTH_REQUEST_SIGNING_ALG, "PS256");
        MultivaluedMap<String, String> form = form();
        form.putSingle("request", signed);
        assertThrows(ErrorResponseException.class, () -> parse(form));
        assertEquals(0, verifications);
    }

    @Test
    public void requestAndRequestUriRemainMutuallyExclusive() throws Exception {
        prepareSignedClaims();
        MultivaluedMap<String, String> form = form();
        form.putSingle("request", signed);
        form.putSingle("request_uri", "https://client.example/request.jwt");
        assertThrows(ErrorResponseException.class, () -> parse(form));
        assertEquals(0, verifications);
    }

    private void prepareSignedClaims() throws Exception {
        String claims = "{\"scope\":\"openid signed\",\"login_hint\":\"signed_user\",\"binding_message\":\"ignored message\","
                + "\"user_code\":\"1234\",\"acr_values\":\"acr2\",\"requested_expiry\":\"not-an-integer\",\"aud\":\"https://issuer.example\"}";
        verifiedClaims = JsonSerialization.readValue(claims, JsonNode.class);
        // Signature verification belongs to TokenManager; the stub controls its success or failure.
        signed = encode("{\"alg\":\"RS256\"}") + "." + encode(claims) + "." + encode("signature");
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private BackchannelAuthenticationEndpointRequest parse(MultivaluedMap<String, String> form) {
        return BackchannelAuthenticationEndpointRequestParserProcessor.parseRequest(null, session, client, form, config);
    }

    private static MultivaluedMap<String, String> form() {
        MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
        form.putSingle("scope", "openid");
        form.putSingle("login_hint", "user_0001");
        form.putSingle("binding_message", "a message with spaces");
        form.putSingle("user_code", "1234");
        form.putSingle("requested_expiry", "60");
        form.putSingle("acr_values", "acr1");
        form.putSingle("client_notification_token", "notification");
        form.putSingle("user_device", "mobile");
        return form;
    }

    private static void assertIgnored(BackchannelAuthenticationEndpointRequest request) {
        assertNull(request.getBindingMessage());
        assertNull(request.getUserCode());
        assertNull(request.getAcr());
        assertNull(request.getRequestedExpiry());
        for (String name : new String[] {"binding_message", "user_code", "acr_values", "requested_expiry"}) {
            assertFalse(request.getAdditionalReqParams().containsKey(name));
        }
    }

    private static <T> T stub(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler));
    }
}
