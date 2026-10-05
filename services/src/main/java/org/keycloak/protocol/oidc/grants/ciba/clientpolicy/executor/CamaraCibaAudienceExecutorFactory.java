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

import java.util.List;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

public class CamaraCibaAudienceExecutorFactory implements ClientPolicyExecutorProviderFactory {

    public static final String PROVIDER_ID = "camara-ciba-audience";

    @Override
    public ClientPolicyExecutorProvider create(KeycloakSession session) {
        return new CamaraCibaAudienceExecutor(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Check signed CIBA request audiences for clients with camara.ciba.enabled=true. Ordinary form requests remain supported.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(new ProviderConfigProperty("additional-audiences", "Additional audiences",
                "Exact public CIBA endpoint URLs accepted in addition to the realm issuer and internal CIBA endpoint. No wildcards or forwarded-header matching.",
                ProviderConfigProperty.MULTIVALUED_STRING_TYPE, null));
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
