/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.crypto.Base64;
import oracle.idm.mobile.crypto.OMKeyManagerException;
import oracle.idm.mobile.crypto.OMKeyStore;
import oracle.idm.mobile.logging.OMLog;

/**
 * Default authenticator that doesn't depend on any user input.
 * <p>
 * Essentially, this is when authentication policy doesn't enforce a PIN
 * or password for the application.
 */
public class OMDefaultAuthenticator extends OMPinAuthenticator {

    private static final String TAG = OMDefaultAuthenticator.class.getSimpleName();
    private KeyProvider keyProvider;
    private String encodedPassword;

    @Override
    public void initialize(Context context, String authenticatorId, OMAuthenticationPolicy authenticationPolicy) throws OMAuthenticationManagerException {

        if (initialized) {
            return;
        }

        super.initialize(context, authenticatorId, authenticationPolicy);
        /* Exceptions can occur below. So, resetting initialized to false,
        which is set to true by the above line.*/
        this.initialized = false;

        if (authenticationPolicy != null && authenticationPolicy.isOkToLoseKeys()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                keyProvider = new AndroidKeyStoreKeyProvider(context);
                Log.v(TAG, "Used AndroidKeyStoreKeyProvider");
            } else {
                keyProvider = new DefaultKeyProvider(context);
                Log.v(TAG, "Used DefaultKeyProvider");
            }
        } else {
            /*Since we do not encrypt the keys, the keys will not be lost when lock screen is
            * removed, or reset by device administrator from Android 6.0 onwards. So, the following
            * will ensure that we never loose the keys.
            * Ref: http://developer.android.com/about/versions/marshmallow/android-6.0-changes.html#behavior-keystore
            * */
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyProvider = new AndroidKeyStoreKeyProvider(context);
                Log.v(TAG, "Used AndroidKeyStoreKeyProvider");
            } else {
                keyProvider = new DefaultKeyProvider(context);
                Log.v(TAG, "Used DefaultKeyProvider");
            }
        }


        byte[] encodedKey = keyProvider.getKey().getEncoded();
        encodedPassword = getPasswordFromKey(encodedKey);
        if (OMSecurityConstants.DEBUG) {
            OMLog.trace(TAG, "**** Inside initialize: encodedPassword = " + encodedPassword);
        }

        this.initialized = true;
    }

    /**
     * Use <code>encodedKey</code> byte array as a 'seed' to generate a
     * String password.
     *
     * @param encodedKey
     * @return
     */
    private String getPasswordFromKey(byte[] encodedKey) {
        byte[] hash = hash(encodedKey);
        return Base64.encode(hash);
    }

    /**
     * SHA-256 based hash.
     *
     * @param input
     * @return
     */
    private byte[] hash(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    @Override
    public boolean authenticate(OMAuthData authData) throws OMAuthenticationManagerException {
        return super.authenticate(new OMAuthData(encodedPassword));
    }

    @Override
    public void copyKeysFrom(OMKeyStore keyStore) {
        oldKeyStore = keyStore;
    }

    @Override
    public void setAuthData(OMAuthData authData) throws OMAuthenticationManagerException {
        if (OMSecurityConstants.DEBUG) {
            OMLog.trace(TAG, "Inside setAuthData: encodedPassword = " + encodedPassword);
        }
        super.setAuthData(new OMAuthData(encodedPassword));
    }

    /**
     * This SHOULD be called to delete the auth data to reset and recover when
     * OMAuthenticationManagerException is thrown from
     * {@link OMDefaultAuthenticator#initialize(Context, String, OMAuthenticationPolicy)}
     * with error code as OMErrorCode.KEY_UNWRAP_FAILED. This happens when Credential store is
     * cleared by user from Settings or when device lock screen is changed in certain scenarios.
     * This is due to the following bug: https://code.google.com/p/android/issues/detail?id=61989
     *
     * @throws OMAuthenticationManagerException
     * @throws OMKeyManagerException
     */
    @Override
    public void deleteAuthData() throws OMAuthenticationManagerException, OMKeyManagerException {
        super.deleteAuthData();
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.JELLY_BEAN_MR2) {
            AndroidKeyStoreKeyProvider keyProvider = new AndroidKeyStoreKeyProvider(context);
            keyProvider.removeKey();
        }

    }

    @Override
    public void updateAuthData(OMAuthData currentAuthData, OMAuthData newAuthData) {
        throw new UnsupportedOperationException("updateAuthData");
    }

}
