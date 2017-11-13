/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

import android.content.Context;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.auth.local.OMAuthenticationManager;
import oracle.idm.mobile.auth.local.OMAuthenticationManagerException;
import oracle.idm.mobile.auth.local.OMAuthenticationPolicy;
import oracle.idm.mobile.auth.local.OMDefaultAuthenticator;
import oracle.idm.mobile.crypto.OMKeyManagerException;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.credentialstore.OMCredentialStore.DEFAULT_AUTHENTICATOR_NAME;

/**
 * This contains utility methods for use by SDK (internally, not for use by SDK consumer)
 * for default authentication purpose.
 *
 * @hide
 */
public class DefaultAuthenticationUtils {
    private static final String TAG = DefaultAuthenticationUtils.class.getSimpleName();

    /**
     * Gets the default authenticator which MUST be used when user has not enabled
     * pin or fingerprint.
     *
     * @param context
     * @return
     * @throws OMAuthenticationManagerException
     */
    public static OMDefaultAuthenticator getDefaultAuthenticator(Context context) throws OMAuthenticationManagerException {
        OMAuthenticationManager authenticationManager = OMAuthenticationManager.getInstance(context);

        try {
            boolean registered = authenticationManager.registerAuthenticator(DEFAULT_AUTHENTICATOR_NAME,
                    OMDefaultAuthenticator.class);
            OMLog.debug(TAG, "Registered: " + registered);
        } catch (OMAuthenticationManagerException e) {
            if (e.getError() == OMErrorCode.INVALID_INPUT) {
                OMLog.debug(TAG, "TO BE IGNORED as default authenticator is already registered: " + e.getMessage());
            } else {
                OMLog.error(TAG, e.getMessage(), e);
                throw e;
            }
        }

        if (!authenticationManager.isEnabled(DEFAULT_AUTHENTICATOR_NAME)) {
            authenticationManager.enableAuthentication(DEFAULT_AUTHENTICATOR_NAME);
        }

        return (OMDefaultAuthenticator) authenticationManager.getAuthenticator(DEFAULT_AUTHENTICATOR_NAME);
    }

    /**
     * Initializes OMDefaultAuthenticator as per SDK requirements.
     *
     * @param context
     * @param defaultAuthenticator
     * @throws OMKeyManagerException
     * @throws OMAuthenticationManagerException
     */
    public static void initializeDefaultAuthenticator(Context context, OMDefaultAuthenticator defaultAuthenticator) throws OMKeyManagerException, OMAuthenticationManagerException {
        if (!defaultAuthenticator.isInitialized()) {
            try {
                OMAuthenticationPolicy authenticationPolicy = new OMAuthenticationPolicy();
                /*Since SDK currently just stores credentials in secure storage, it is fine to loose
                * keys because it provides better security. Refer javadoc of OMAuthenticationPolicy#setOkToLoseKeys.
                * Credentials can be reentered by user in case the keys are lost.
                * */
                authenticationPolicy.setOkToLoseKeys(true);
                defaultAuthenticator.initialize(context, DEFAULT_AUTHENTICATOR_NAME, authenticationPolicy);
            } catch (OMAuthenticationManagerException e) {
                if (e.getError() == OMErrorCode.KEY_UNWRAP_FAILED) {
                    OMLog.error(TAG, e.getMessage(), e);
                    OMLog.debug(TAG, "Resetting default authenticator");
                    defaultAuthenticator.deleteAuthData();
                    initializeDefaultAuthenticator(context, defaultAuthenticator);
                } else {
                    OMLog.error(TAG, e.getMessage(), e);
                    throw e;
                }
            }

        }
        defaultAuthenticator.setAuthData(null);
        if (!defaultAuthenticator.isAuthenticated()) {
            OMLog.debug(TAG, "Going to perform default local auth");
            defaultAuthenticator.authenticate(null);
        }
    }

}
