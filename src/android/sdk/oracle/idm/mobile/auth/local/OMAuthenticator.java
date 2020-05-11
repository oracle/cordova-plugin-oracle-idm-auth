/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import android.content.Context;

import oracle.idm.mobile.crypto.OMKeyManagerException;
import oracle.idm.mobile.crypto.OMKeyStore;

/**
 * Authenticator interface.
 *
 */
public interface OMAuthenticator {

    /**
     * names authenticator instance to authenticatorName. If authPolicy is passed then authenticator
     * will take care of  authPolicy implementation
     * @param context
     * @param authenticatorId
     * @param authenticationPolicy may be null
     */
    void initialize(Context context, String authenticatorId, OMAuthenticationPolicy authenticationPolicy) throws OMAuthenticationManagerException;


    /**
     * When authenticator is changed, say from {@link OMDefaultAuthenticator} to {@link OMPinAuthenticator},
     * the keys should be migrated (or moved) from previous keystore to new keystore. For this purpose,
     * this method should be called before calling setAuthData in the new {@link OMAuthenticator}.
     * @param keyStore
     */
    void copyKeysFrom(OMKeyStore keyStore);

    /**
     * Sets authentication data. It will internally perform operation to secure auth data and store it in storage.
     * @param authData
     */
    void setAuthData(OMAuthData authData) throws OMAuthenticationManagerException;


    /**
     * Deletes auth data already stored in storage.
     */
    void deleteAuthData() throws OMKeyManagerException, OMAuthenticationManagerException;


    /**
     * This method updates the old authData with new Auth data
     *
     * @param currentAuthData currently set auth data
     * @param newAuthData     new auth data to replace the existing one
     */
    void updateAuthData(OMAuthData currentAuthData, OMAuthData newAuthData) throws OMKeyManagerException, OMAuthenticationManagerException;

    /**
     * Authenticates auth data passed and return true if successful else false.
     * @param authData
     * @return
     * @throws OMAuthenticationManagerException for null or invalid auth data
     */
    boolean authenticate(OMAuthData authData) throws OMAuthenticationManagerException;


    /**
     * Return state of authentication, true if authentication was successful else false.
     * @return
     */
    boolean isAuthenticated();

    /**
     * Whether or not this authenticator ins initialized.
     * @return
     */
    boolean isInitialized();

    /**
     * True if <code>OMAuthData</code> for this authenticator is set.
     * @return
     */
    boolean isAuthDataSet();

    /**
     * Invalidates authentication status to false.
     */
    void invalidate();

    /**
     * returns key store object associated with authenticator.
     * @return
     */
    OMKeyStore getKeyStore();
}
