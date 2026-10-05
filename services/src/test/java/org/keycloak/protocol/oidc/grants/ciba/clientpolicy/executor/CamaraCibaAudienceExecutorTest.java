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

package org.keycloak.protocol.oidc.grants.ciba.clientpolicy.executor;

import java.util.Set;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.List;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.MultivaluedHashMap;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.UrlType;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.protocol.oidc.grants.ciba.clientpolicy.context.BackchannelAuthenticationRequestContext;
import org.keycloak.protocol.oidc.grants.ciba.endpoints.request.BackchannelAuthenticationEndpointRequest;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;
import org.keycloak.OAuthErrorException;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.util.JsonSerialization;

import static org.junit.Assert.*;

public class CamaraCibaAudienceExecutorTest {
    private static final Set<String> ALLOWED = Set.of("https://issuer.example/realms/test", "https://api.example/bc-authorize");

    @Test
    public void acceptsExactIssuerAndConfiguredPublicEndpoint() throws Exception {
        for (String audience : ALLOWED) {
            CamaraCibaAudienceExecutor.validateAudience(claims("\"" + audience + "\""), ALLOWED);
        }
    }

    @Test
    public void acceptsArrayWithAnAllowedAudience() throws Exception {
        CamaraCibaAudienceExecutor.validateAudience(claims("[\"https://other.example\",\"https://api.example/bc-authorize\"]"), ALLOWED);
    }

    @Test
    public void rejectsMissingNullMalformedOrUnmatchedAudience() throws Exception {
        for (String audience : new String[] {"null", "42", "{}", "[]", "[42]",
                "[\"https://api.example/bc-authorize\",42]", "\"https://api.example/bc-authorize/extra\"",
                "\"https://attacker.example\""}) {
            JsonNode claims = claims(audience);
            ClientPolicyException error = assertThrows(ClientPolicyException.class,
                    () -> CamaraCibaAudienceExecutor.validateAudience(claims, ALLOWED));
            assertEquals(OAuthErrorException.INVALID_REQUEST, error.getError());
            assertEquals("Invalid audience", error.getErrorDetail());
        }
        assertThrows(ClientPolicyException.class, () -> CamaraCibaAudienceExecutor.validateAudience(null, ALLOWED));
        JsonNode missing = JsonSerialization.readValue("{}", JsonNode.class);
        assertThrows(ClientPolicyException.class, () -> CamaraCibaAudienceExecutor.validateAudience(missing, ALLOWED));
    }

    @Test
    public void configurationSupportsExplicitAudienceListAndNull() throws Exception {
        CamaraCibaAudienceExecutor.Configuration config = JsonSerialization.readValue(
                "{\"additional-audiences\":[\"https://api.example/bc-authorize\"]}", CamaraCibaAudienceExecutor.Configuration.class);
        assertEquals(List.of("https://api.example/bc-authorize"), config.getAdditionalAudiences());
        config.setAdditionalAudiences(null);
        assertTrue(config.getAdditionalAudiences().isEmpty());
    }

    @Test
    public void executorChecksSignedRequestAndRequestUriBeforeTheChannel() throws Exception {
        for (String parameter : new String[] {"request", "request_uri"}) {
            for (String audience : new String[] {"https://keycloak.example/realms/test",
                    "https://keycloak.example/realms/test/protocol/openid-connect/ext/ciba/auth",
                    "https://api.example/bc-authorize"}) {
                execute("true", parameter, claims("\"" + audience + "\""));
            }
            assertThrows(ClientPolicyException.class, () -> execute("true", parameter, claims("\"https://attacker.example\"")));
            assertThrows(ClientPolicyException.class, () -> execute("true", parameter, null));
        }
    }

    @Test
    public void executorLeavesOtherClientsAndOrdinaryFormsAlone() throws Exception {
        execute(null, "request", null);
        execute("false", "request", null);
        execute("true", null, null);
        // Non-CIBA events must not even access the session.
        new CamaraCibaAudienceExecutor(null).executeOnEvent(() -> ClientPolicyEvent.TOKEN_REQUEST);
    }

    private static void execute(String enabled, String parameter, JsonNode claims) throws Exception {
        ClientModel client = stub(ClientModel.class,
                (p, m, a) -> enabled);
        RealmModel realm = stub(RealmModel.class,
                (p, m, a) -> "test");
        HostnameProvider hostname = stub(HostnameProvider.class, (p, m, a) -> {
            switch (m.getName()) {
                case "getHostname": return "keycloak.example";
                case "getScheme": return "https";
                case "getPort": return -1;
                case "getContextPath": return "/";
                default: throw new AssertionError(m.getName());
            }
        });
        UriInfo uri = stub(UriInfo.class,
                (p, m, a) -> UriBuilder.fromUri("https://keycloak.example/"));
        KeycloakSession hostnameSession = stub(KeycloakSession.class,
                (p, m, a) -> hostname);
        KeycloakUriInfo keycloakUri = new KeycloakUriInfo(
                hostnameSession, UrlType.FRONTEND, uri);
        KeycloakContext context = stub(KeycloakContext.class, (p, m, a) -> {
            switch (m.getName()) {
                case "getClient": return client;
                case "getRealm": return realm;
                case "getUri": return keycloakUri;
                default: throw new AssertionError(m.getName());
            }
        });
        KeycloakSession session = stub(KeycloakSession.class, (p, m, a) -> {
            switch (m.getName()) {
                case "getContext": return context;
                case "getAttribute": return claims;
                default: throw new AssertionError(m.getName());
            }
        });
        CamaraCibaAudienceExecutor executor = new CamaraCibaAudienceExecutor(session);
        CamaraCibaAudienceExecutor.Configuration configuration = new CamaraCibaAudienceExecutor.Configuration();
        configuration.setAdditionalAudiences(List.of("https://api.example/bc-authorize"));
        executor.setupConfiguration(configuration);
        MultivaluedMap<String, String> parameters = new MultivaluedHashMap<>();
        if (parameter != null) parameters.putSingle(parameter, "original signed request or URI");
        executor.executeOnEvent(new BackchannelAuthenticationRequestContext(
                new BackchannelAuthenticationEndpointRequest(), null, parameters));
    }

    private static <T> T stub(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler));
    }

    private static JsonNode claims(String audience) throws Exception {
        return JsonSerialization.readValue("{\"aud\":" + audience + "}", JsonNode.class);
    }
}
