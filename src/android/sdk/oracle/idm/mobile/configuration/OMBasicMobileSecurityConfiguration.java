/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

package oracle.idm.mobile.configuration;

import android.content.Context;

import java.net.MalformedURLException;
import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.connection.OMConnectionHandler;

/**
 * This class implementation assumes that all the required configuration parameters are supplied through its
 * constructor and the {@link OMMobileSecurityConfiguration#initialize(Context, OMConnectionHandler)} method in this class will do nothing.
 *
 */
public class OMBasicMobileSecurityConfiguration extends
        OMMobileSecurityConfiguration {
    /**
     * This creates an object which holds configuration details to perform HTTP
     * Basic Authentication.
     *
     * @param configProperties Map of configuration properties with keys like
     *                         {@link OMMobileSecurityService#OM_PROP_LOGIN_URL},
     *                         {@link OMMobileSecurityService#OM_PROP_LOGOUT_URL}, etc.
     */
    OMBasicMobileSecurityConfiguration(Map<String, Object> configProperties) throws OMMobileSecurityException {
        super(configProperties);
        try {
            this.authenticationScheme = OMAuthenticationScheme.BASIC;

            parseLoginURL(configProperties);
            parseLogoutURL(configProperties);

            parseRequiredTokens(configProperties);
            parseIdentityDomainProperties(configProperties);
            parseIdleTimeout(configProperties);
            parseSessionTimeout(configProperties);
            parseCustomAuthHeaders(configProperties);
            parseAuthzHeaderInLogout(configProperties);
            parseSendCustomAuthHeadersInLogout(configProperties);
            parseOfflinePreferences(configProperties);
            parseClientCertPreference(configProperties);
            //flags to control the parsing of Remember credential flags.
            int rcConfigFlags = 0;
            rcConfigFlags |= FLAG_ENABLE_AUTO_LOGIN;
            rcConfigFlags |= FLAG_ENABLE_REMEMBER_CREDENTIALS;
            rcConfigFlags |= FLAG_ENABLE_REMEMBER_USERNAME;
            parseRememberCredentials(configProperties, rcConfigFlags);
            isInitialized = true;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void initialize(Context context, OMConnectionHandler handler) throws OMMobileSecurityException {

    }
}
