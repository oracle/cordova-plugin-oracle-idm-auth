/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.crypto.Base64;
import oracle.idm.mobile.crypto.OMKeyManager;
import oracle.idm.mobile.crypto.OMKeyManagerException;
import oracle.idm.mobile.crypto.OMKeyStore;
import oracle.idm.mobile.crypto.OMSecureStorageException;
import oracle.idm.mobile.crypto.OMSecureStorageService;

/**
 * Fingerprint based authenticator.
 *
 */
public class OMFingerprintAuthenticator implements OMAuthenticator {

    private static final String TAG = OMFingerprintAuthenticator.class.getSimpleName();
    private static final String ALIAS_KEK = "kek_fingerprint_authenticator";

    private String authenticatorId;
    private OMAuthenticationPolicy authenticationPolicy;
    private Context context;
    private boolean initialized;
    private OMPinAuthenticator pinAuthenticator;
    private OMKeyStore omKeyStore;
    private boolean authenticated;
    private SecretKeyWrapper secretKeyWrapper;

    public OMFingerprintAuthenticator() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            throw new IllegalStateException("OMFingerprintAuthenticator does not work in android versions below Marshmallow");
        }
    }

    /**
     * {@link OMFingerprintAuthenticator#setBackupAuthenticator(OMPinAuthenticator pinAuthenticator)} MUST BE called after calling this method.
     *
     * @param context
     * @param authenticatorId
     * @param authenticationPolicy may be null
     * @throws OMAuthenticationManagerException
     */
    @Override
    public void initialize(Context context, String authenticatorId, OMAuthenticationPolicy authenticationPolicy) throws OMAuthenticationManagerException {
        if (initialized) {
            return;
        }

        if (context == null) {
            throw new IllegalArgumentException("context cannot be null");
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
        /* Since OMFingerprintAuthenticator uses the same keystore as the
        OMFingerprintAuthenticator#setBackupAuthenticator(),
        there is no need to copy the keys from OMPinAuthenticator to OMFingerprintAuthenticator.
         */

    }

    /**
     * Sets authentication data. It will internally perform operation to secure auth data and store it in storage.
     *
     * @param authData The data should be the PIN used as backup authentication for fingerprint.
     * @throws OMAuthenticationManagerException One possible error code is OMErrorCode.NO_FINGERPRINT_ENROLLED.
     */
    @Override
    public void setAuthData(OMAuthData authData) throws OMAuthenticationManagerException {
        ensureInitialized();

        if (authData == null) {
            throw new NullPointerException("authData");
        }

        if (!(authData.getData() instanceof String)) {
            String className = authData.getData().getClass().getName();
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "OMAuthData.getData() must return a String object, not [" + className + "]");
        }

        doSetAuthData(authData);
    }

    private void doSetAuthData(OMAuthData authData) throws OMAuthenticationManagerException {
        String pin = (String) authData.getData();
        byte[] salt = Base64.decode(pinAuthenticator.getSharedPreferences().getString(pinAuthenticator.getSharedPreferencesKeyForSalt(), null));
        if (salt == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "No salt.");
        }

        Key kek = pinAuthenticator.getKeyFromPin(pin, salt);
        SecretKey kekSecretKey = new SecretKeySpec(kek.getEncoded(), "AES");
        try {
            byte[] wrapped = getSecretKeyWrapper().wrap(kekSecretKey);
            String wrappedKeyString = Base64.encode(wrapped);
            PreferenceManager.getDefaultSharedPreferences(context).edit().putString(ALIAS_KEK, wrappedKeyString).apply();
            Log.v(TAG, "authData set successfully");
        } catch (GeneralSecurityException e) {
            Log.e(TAG, e.getMessage(), e);
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    @Override
    public void deleteAuthData() throws OMKeyManagerException, OMAuthenticationManagerException {
        ensureInitialized();

        if (!authenticated) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "Not authenticated");
        }

        try {
            PreferenceManager.getDefaultSharedPreferences(context).edit().remove(ALIAS_KEK).commit();

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(ALIAS_KEK);
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, "Cannot delete public-private keypair", e);
        }
        invalidate();
    }

    /**
     * The currentAuthData MUST have the current PIN and newAuthData MUST have the new PIN. This will
     * internally call {@link OMPinAuthenticator#updateAuthData(OMAuthData, OMAuthData)} in addition to
     * updating authData for this fingerprint authenticator instance.
     *
     * @param currentAuthData
     * @param newAuthData
     * @throws OMKeyManagerException
     * @throws OMAuthenticationManagerException
     */
    @Override
    public void updateAuthData(OMAuthData currentAuthData, OMAuthData newAuthData) throws OMKeyManagerException, OMAuthenticationManagerException {
        ensureInitialized();

        // Since for updation, we will use the salt generated by PinAuthenticator in OMFingerprintAuthenticator#doSetAuthData,
        // we MUST update pinAuthenticator authData first.
        pinAuthenticator.updateAuthData(currentAuthData, newAuthData);
        Log.v(TAG, "Updated authData for backup pin authenticator");

        if (!authenticated) {
            authenticate(currentAuthData);
            if (!authenticated) {
                throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE,
                        "Cannot authenticate using currentAuthData");
            }
        }

        if (newAuthData == null) {
            throw new NullPointerException("newAuthData");
        }

        if (!(newAuthData.getData() instanceof String)) {
            String className = newAuthData.getData().getClass().getName();
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "OMAuthData.getData() must return a String object not [" + className + "]");
        }

        doSetAuthData(newAuthData);
        Log.v(TAG, "Updated authData for fingerprint authenticator");
    }

    /**
     * User MUST  be authenticated using AndroidFingerprint APIs and then pass FingerprintManager.CryptoObject (obtained after successful authentication)
     * in authData. This API will decrypt keystore with the FingerprintManager.CryptoObject.
     * <p/>
     * If user is to be authenticated using backup PIN, the PIN entered by user MUST be passed in authData.
     *
     * @param authData
     * @return
     * @throws OMAuthenticationManagerException
     */
    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public boolean authenticate(OMAuthData authData) throws OMAuthenticationManagerException {
        ensureInitialized();

        if (authData == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "authData not set");
        }

        if (!(authData.getData() instanceof FingerprintManager.CryptoObject || authData.getData() instanceof String)) {
            String className = authData.getData().getClass().getName();
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "OMAuthData.getData() must return a FingerprintManager.CryptoObject object or a String object, not [" + className + "]");
        }

        if (authData.getData() instanceof FingerprintManager.CryptoObject) {
            SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(context);
            String wrappedKeyString = sp.getString(ALIAS_KEK, null);

            if (wrappedKeyString == null) {
                throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE, "KEK cannot be null here");
            }
            byte[] blob = Base64.decode(wrappedKeyString);
            FingerprintManager.CryptoObject cryptoObject = (FingerprintManager.CryptoObject) authData.getData();
            try {
                SecretKey secretKey = (SecretKey) cryptoObject.getCipher().unwrap(blob, "AES", Cipher.SECRET_KEY);

                OMKeyManager keyManager = new OMKeyManager(context);
                omKeyStore = keyManager.getKeyStore(pinAuthenticator.authenticatorId, secretKey.getEncoded());

                OMSecureStorageService secureStorageService = new OMSecureStorageService(context, omKeyStore, pinAuthenticator.authenticatorId);
                String randomDataStorageKey = pinAuthenticator.getSharedPreferencesKeyForPinValidationData();
                String validationData1 = pinAuthenticator.getSharedPreferences().getString(randomDataStorageKey, null);
                String validationDate2 = (String) secureStorageService.get(randomDataStorageKey);
                if (validationData1 != null && validationData1.equals(validationDate2)) {
                    authenticated = true;
                    return true;
                }
                return false;
            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                Log.e(TAG, e.getMessage(), e);
                throw new OMAuthenticationManagerException(OMErrorCode.KEY_UNWRAP_FAILED, e);
            } catch (OMKeyManagerException | OMSecureStorageException e) {
                Log.e(TAG, e.getMessage(), e);
                throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e);
            }
        } else {
            authenticated = pinAuthenticator.authenticate(authData);
            return authenticated;
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
        String wrappedKeyString = PreferenceManager.getDefaultSharedPreferences(context).getString(ALIAS_KEK, "");
        return !TextUtils.isEmpty(wrappedKeyString);
    }

    @Override
    public void invalidate() {
        initialized = false;
        authenticated = false;
        omKeyStore = null;
        secretKeyWrapper = null;
    }

    @Override
    public OMKeyStore getKeyStore() {
        if (omKeyStore != null) {
            return omKeyStore;
        } else if (pinAuthenticator != null) {
            /* omKeyStore will be initialized only if authentication is done using fingerprint.
            * Since, key store of OMFingerprintAuthenticator is same as keystore of its backup OMPinAuthenticator,
            * we return KeyStore of OMPinAuthenticator here. So, if user has done authentication using backup PIN,
            * this API will still be returning a valid keystore.*/
            return pinAuthenticator.getKeyStore();
        }
        return null;
    }

    /**
     * This provides FingerprintManager.CryptoObject to be passed in
     * {@link FingerprintManager#authenticate(FingerprintManager.CryptoObject, CancellationSignal, int, FingerprintManager.AuthenticationCallback, Handler)}
     * to authenticate the user using Android Fingerprint APIs. Once the authentication is done, the same object MUST be passed using
     * {@link OMFingerprintAuthenticator#authenticate(OMAuthData)}.
     *
     * @return
     * @throws GeneralSecurityException
     * @throws OMAuthenticationManagerException One possible error code is OMErrorCode.NO_FINGERPRINT_ENROLLED.
     * @throws OMKeyManagerException
     * @throws IOException
     */
    @TargetApi(Build.VERSION_CODES.M)
    public FingerprintManager.CryptoObject getFingerprintManagerCryptoObject() throws GeneralSecurityException, OMAuthenticationManagerException, OMKeyManagerException, IOException {
        ensureInitialized();
        return new FingerprintManager.CryptoObject(getSecretKeyWrapper().getUnwrapCipher());
    }

    public void setBackupAuthenticator(OMPinAuthenticator pinAuthenticator) {
        this.pinAuthenticator = pinAuthenticator;
    }

    private void ensureInitialized() throws OMAuthenticationManagerException {
        if (!isInitialized()) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE,
                    "Authenticator is not initialized. Did you call initialize() method?");
        }
    }

    private SecretKeyWrapper getSecretKeyWrapper() throws OMAuthenticationManagerException {
        if (secretKeyWrapper == null) {
            try {
                Log.v(TAG, "Initializing SecretKeyWrapper");
                secretKeyWrapper = new SecretKeyWrapper(context, ALIAS_KEK, true);
            } catch (InvalidAlgorithmParameterException e) {
            /*This happens every time when emulator is restarted. Though a fingerprint is registered, the stacktrace indicates:
             Caused by: java.security.InvalidAlgorithmParameterException: java.lang.IllegalStateException: At least one fingerprint must be enrolled to create keys requiring user authentication for every use
             This seems to be a bug in emulator. This should not arise in a device.
            * */
                throw new OMAuthenticationManagerException(OMErrorCode.NO_FINGERPRINT_ENROLLED, e.getMessage(), e);
            } catch (GeneralSecurityException | IOException e) {
                throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
            }
        }
        return secretKeyWrapper;
    }
}
