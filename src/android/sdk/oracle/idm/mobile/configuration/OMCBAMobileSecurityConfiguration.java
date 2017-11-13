/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

import android.content.Context;

import java.net.MalformedURLException;
import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.connection.OMConnectionHandler;

/**
 * Hold configuration for Client Certificate based authentication, in standalone mode.
 *
 * @hide
 */
public class OMCBAMobileSecurityConfiguration extends OMMobileSecurityConfiguration {

    /**
     * This constructor can be used to do any common initialization across
     * implementations.
     *
     * @param configProperties
     */
    protected OMCBAMobileSecurityConfiguration(Map<String, Object> configProperties) throws OMMobileSecurityException {
        super(configProperties);
        this.authenticationScheme = OMAuthenticationScheme.CBA;
        mClientCertificateEnabled = true;//enables the property by default
        try {
            parseLoginURL(configProperties);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid Login URL");
        }
//        parseSessionTimeout(configProperties);
//        parseIdleTimeout(configProperties);
        parseForCustomAuthHeaders(configProperties);
        isInitialized = true;
    }

    @Override
    public void initialize(Context context, OMConnectionHandler handler) throws OMMobileSecurityException {

        // no op as of now.
    }
}
