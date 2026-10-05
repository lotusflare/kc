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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.OAuthErrorException;
import org.keycloak.models.CibaConfig;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.ciba.CibaGrantType;
import org.keycloak.protocol.oidc.grants.ciba.clientpolicy.context.BackchannelAuthenticationRequestContext;
import org.keycloak.protocol.oidc.grants.ciba.endpoints.request.BackchannelAuthenticationEndpointRequestParser;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

/** Checks the audience of an already verified CIBA request without replacing the endpoint. */
public class CamaraCibaAudienceExecutor implements ClientPolicyExecutorProvider<CamaraCibaAudienceExecutor.Configuration> {

    private final KeycloakSession session;
    private Configuration configuration = new Configuration();

    public CamaraCibaAudienceExecutor(KeycloakSession session) {
        this.session = session;
    }

    public static class Configuration extends ClientPolicyExecutorConfigurationRepresentation {
        @JsonProperty("additional-audiences")
        protected List<String> additionalAudiences = List.of();

        public List<String> getAdditionalAudiences() {
            return additionalAudiences;
        }

        public void setAdditionalAudiences(List<String> additionalAudiences) {
            this.additionalAudiences = additionalAudiences == null ? List.of() : additionalAudiences;
        }
    }

    @Override
    public void setupConfiguration(Configuration configuration) {
        this.configuration = configuration == null ? new Configuration() : configuration;
    }

    @Override
    public Class<Configuration> getExecutorConfigurationClass() {
        return Configuration.class;
    }

    @Override
    public String getProviderId() {
        return CamaraCibaAudienceExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        if (context.getEvent() != ClientPolicyEvent.BACKCHANNEL_AUTHENTICATION_REQUEST) {
            return;
        }
        ClientModel client = session.getContext().getClient();
        if (client == null || !Boolean.parseBoolean(client.getAttribute(CibaConfig.CAMARA_CIBA_ENABLED))) {
            return;
        }
        BackchannelAuthenticationRequestContext cibaContext = (BackchannelAuthenticationRequestContext) context;
        var parameters = cibaContext.getRequestParameters();
        if (parameters.getFirst(OIDCLoginProtocol.REQUEST_PARAM) == null
                && parameters.getFirst(OIDCLoginProtocol.REQUEST_URI_PARAM) == null) {
            return; // Ordinary form requests remain supported.
        }

        // Keycloak's signed-request parser verifies the signature and saves these claims.
        JsonNode claims = (JsonNode) session.getAttribute(BackchannelAuthenticationEndpointRequestParser.CIBA_SIGNED_AUTHENTICATION_REQUEST);
        String realmName = session.getContext().getRealm().getName();
        Set<String> audiences = new HashSet<>(configuration.getAdditionalAudiences());
        audiences.add(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realmName));
        audiences.add(CibaGrantType.authorizationUrl(session.getContext().getUri().getBaseUriBuilder()).build(realmName).toString());
        validateAudience(claims, audiences);
    }

    static void validateAudience(JsonNode claims, Set<String> allowed) throws ClientPolicyException {
        JsonNode audience = claims == null ? null : claims.get("aud");
        if (audience != null) {
            if (audience.isTextual() && allowed.contains(audience.textValue())) {
                return;
            }
            if (audience.isArray() && !audience.isEmpty()) {
                boolean matches = false;
                for (JsonNode entry : audience) {
                    if (!entry.isTextual()) {
                        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid audience");
                    }
                    matches |= allowed.contains(entry.textValue());
                }
                if (matches) {
                    return;
                }
            }
        }
        throw new ClientPolicyException(OAuthErrorException.INVALID_REQUEST, "Invalid audience");
    }
}
