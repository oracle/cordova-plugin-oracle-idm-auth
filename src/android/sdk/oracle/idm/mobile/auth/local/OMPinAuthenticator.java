/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.crypto.Base64;
import oracle.idm.mobile.crypto.OMInvalidKeyException;
import oracle.idm.mobile.crypto.OMKeyManager;
import oracle.idm.mobile.crypto.OMKeyManagerException;
import oracle.idm.mobile.crypto.OMKeyStore;
import oracle.idm.mobile.crypto.OMSecureStorageService;
import oracle.idm.mobile.logging.OMLog;

/**
 * PIN based authenticator.
 */
public class OMPinAuthenticator implements OMAuthenticator {

    private static final String TAG = OMPinAuthenticator.class.getSimpleName();

    protected String authenticatorId;
    protected OMAuthenticationPolicy authenticationPolicy;
    protected Context context;

    protected OMKeyStore keyStore;

    protected boolean authenticated = false;
    protected boolean initialized = false;

    private Key kek;
    protected OMKeyStore oldKeyStore;

    public OMPinAuthenticator() {
    }

    SharedPreferences getSharedPreferences() {
        return context.getSharedPreferences(OMPinAuthenticator.class.getSimpleName(),
                Context.MODE_PRIVATE);
    }

    String getSharedPreferencesKeyForSalt() {
        return this.authenticatorId + "_salt";
    }

    String getSharedPreferencesKeyForPinValidationData() {
        return this.authenticatorId + "_validation_data";
    }

    @Override
    public void initialize(Context context, String authenticatorId, OMAuthenticationPolicy authenticationPolicy) throws OMAuthenticationManagerException {

        if (initialized) {
            return;
        }

        if (TextUtils.isEmpty(authenticatorId)) {
            throw new NullPointerException("authenticatorId");
        }

        this.authenticatorId = authenticatorId;
        this.authenticationPolicy = authenticationPolicy;
        this.context = context;
        initialized = true;
    }

    @Override
    public void copyKeysFrom(OMKeyStore keyStore) {
        oldKeyStore = keyStore;
    }

    @Override
    public void setAuthData(OMAuthData authData) throws OMAuthenticationManagerException {
        if (authData == null) {
            throw new NullPointerException("authData");
        }

        if (authData.getData() == null) {
            throw new NullPointerException("authData.getData()");
        }

        if (!(authData.getData() instanceof String)) {
            String className = authData.getData().getClass().getName();
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "OMAuthData.getData() must return a String object not [" + className + "]");
        }

        String pin = (String) authData.getData();
        String storedSalt = getSharedPreferences().getString(getSharedPreferencesKeyForSalt(), null);
        byte[] salt;
        if (storedSalt == null) {
            salt = getSalt();
        } else {
            salt = Base64.decode(storedSalt);
        }
        doSetAuthData(pin, salt);
    }

    /**
     * Common logic to set auth data.
     *
     * @param pin
     * @param salt
     */
    private void doSetAuthData(String pin, byte[] salt) throws OMAuthenticationManagerException {
        try {
            kek = getKeyFromPin(pin, salt);
            if (OMSecurityConstants.DEBUG) {
                OMLog.trace(TAG, "**** Inside doSetAuthData: kek = " + Base64.encode(kek.getEncoded()));
            }
            OMKeyManager keyManager = new OMKeyManager(context);

            try {
                keyStore = keyManager.getKeyStore(authenticatorId, kek.getEncoded());
            } catch (OMInvalidKeyException e) {
                throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR,
                        "Invalid key. The given key is not valid to decrypt the encrypted data.", e);
            } catch (OMKeyManagerException ignored) {
            }

            if (keyStore == null) {
                keyStore = keyManager.createKeyStore(authenticatorId, kek.getEncoded());
                keyStore.createKey(authenticatorId, true);
            }

            if (oldKeyStore != null) {
                keyStore.copyKeysFrom(oldKeyStore);
            }

            OMSecureStorageService secureStorageService = new OMSecureStorageService(context, keyStore, authenticatorId);

            String randomDataStorageKey = getSharedPreferencesKeyForPinValidationData();
            String randomData = getRandomString();

            secureStorageService.store(randomDataStorageKey, randomData);

            getSharedPreferences().edit()
                    .putString(randomDataStorageKey, randomData)
                    .putString(getSharedPreferencesKeyForSalt(), Base64.encode(salt))
                    .commit();
        } catch (Exception e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    Key getKeyFromPin(String pin, byte[] salt) throws OMAuthenticationManagerException {

        long start = System.currentTimeMillis();
        int iterations = 2000;
        int keyLengthInBits = /* 32 bytes = */ 256;
        char[] chars = pin.toCharArray();

        KeySpec spec = new PBEKeySpec(chars, salt, iterations, keyLengthInBits);

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKey key = skf.generateSecret(spec);
            long end = System.currentTimeMillis() - start;
            OMLog.debug("getKeyFromPin", "getKeyFromPin took:  " + end + " ms");
            return key;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    /**
     * Randomly generated salt.
     *
     * @return
     */
    private byte[] getSalt() {
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    /**
     * Random 64 bytes long string.
     *
     * @return
     */
    private String getRandomString() {
        SecureRandom sr = new SecureRandom();
        byte[] data = new byte[64];
        sr.nextBytes(data);
        return Base64.encode(data);
    }


    @Override
    public void deleteAuthData() throws OMKeyManagerException, OMAuthenticationManagerException {
        if (!authenticated) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "Not authenticated");
        }

        OMKeyManager keyManager = new OMKeyManager(context);
        keyManager.deleteKeyStore(authenticatorId, kek.getEncoded());
        getSharedPreferences().edit().
                remove(getSharedPreferencesKeyForPinValidationData())
                .remove(getSharedPreferencesKeyForSalt())
                .commit();

        invalidate();
    }

    @Override
    public void updateAuthData(OMAuthData currentAuthData, OMAuthData newAuthData) throws OMKeyManagerException, OMAuthenticationManagerException {

        boolean authenticated;
        try {
            authenticated = authenticate(currentAuthData);
        } catch (OMAuthenticationManagerException e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INCORRECT_CURRENT_AUTHDATA,
                    "Cannot authenticate using currentAuthData", e);
        }
        if (!authenticated) {
            throw new OMAuthenticationManagerException(OMErrorCode.INCORRECT_CURRENT_AUTHDATA,
                    "Cannot authenticate using currentAuthData");
        }

        if (newAuthData == null) {
            throw new NullPointerException("newAuthData");
        }

        if (newAuthData.getData() == null) {
            throw new NullPointerException("newAuthData.getData()");
        }

        if (!(newAuthData.getData() instanceof String)) {
            String className = newAuthData.getData().getClass().getName();
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "OMAuthData.getData() must return a String object not [" + className + "]");
        }


        String newPin = (String) newAuthData.getData();
        byte[] newSalt = getSalt();
        Key newKey = getKeyFromPin(newPin, newSalt);

        OMKeyManager keyManager = new OMKeyManager(context);

        keyManager.updateEncryptionKey(authenticatorId, kek.getEncoded(), newKey.getEncoded());
        doSetAuthData(newPin, newSalt);
    }

    @Override
    public boolean authenticate(OMAuthData authData) throws OMAuthenticationManagerException {
        if (!initialized) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "Authenticator not yet initialized.");
        }

        if (authData == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "authData not set");
        }

        if (!(authData.getData() instanceof String)) {
            String className = authData.getData().getClass().getName();
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "OMAuthData.getData() must return a String object not [" + className + "]");
        }

        String pin = (String) authData.getData();
        byte[] salt = Base64.decode(getSharedPreferences().getString(getSharedPreferencesKeyForSalt(), null));
        if (salt == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "No salt.");
        }

        try {
            Key localKek;
            OMKeyStore localKeyStore;
            localKek = getKeyFromPin(pin, salt);
            if (OMSecurityConstants.DEBUG) {
                OMLog.trace(TAG, "**** Inside authenticate: KEK = " + Base64.encode(localKek.getEncoded()));
            }
            OMKeyManager keyManager = new OMKeyManager(context);
            localKeyStore = keyManager.getKeyStore(authenticatorId, localKek.getEncoded());
            OMSecureStorageService secureStorageService = new OMSecureStorageService(context, localKeyStore, authenticatorId);

            String randomDataStorageKey = getSharedPreferencesKeyForPinValidationData();
            String validationData1 = getSharedPreferences().getString(randomDataStorageKey, null);
            String validationDate2 = (String) secureStorageService.get(randomDataStorageKey);
            if (validationData1 != null && validationData1.equals(validationDate2)) {
                authenticated = true;
                /* The new kek and keystore created in this method
                 * should overwrite corres. member variables only
                 * if authentication is successful.*/
                kek = localKek;
                keyStore = localKeyStore;
                return true;
            }
            return false;
        } catch (Exception e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }

    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    @Override
    public boolean isAuthDataSet() {
        if (context == null) {
            return false;
        }
        String dataKey = getSharedPreferencesKeyForPinValidationData();
        return getSharedPreferences().getString(dataKey, null) != null;
    }

    @Override
    public void invalidate() {
        initialized = false;
        authenticated = false;
        keyStore = null;
        oldKeyStore = null;
        kek = null;
    }

    @Override
    public OMKeyStore getKeyStore() {
        return keyStore;
    }

    private void ensureInitialized() throws OMAuthenticationManagerException {
        if (!isInitialized()) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE,
                    "Authenticator is not initialized. Did you call initialize() method?");
        }
    }
}
