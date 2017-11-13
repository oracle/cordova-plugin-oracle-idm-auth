/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.crypto.Base64;

/**
 * A key provider that uses Android's 4.3+'s underlying
 * {@link KeyStore} for storing key.
 */
public class AndroidKeyStoreKeyProvider implements KeyProvider {

    private static final String DEFAULT_KEY_ALIAS = OMDefaultAuthenticator.class.getSimpleName() + "_default_key";

    private Context context;

    public AndroidKeyStoreKeyProvider(Context context) throws OMAuthenticationManagerException {
        this.context = context;

        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.JELLY_BEAN_MR2) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR,
                    "Android KeyStore is supported only for JELLY_BEAN_MR2 or later.");
        }
    }

    @Override
    public Key getKey() throws OMAuthenticationManagerException {
        try {

            SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(context);
            String wrappedKeyString = sp.getString(DEFAULT_KEY_ALIAS, null);

            SecretKeyWrapper keyWrapper = new SecretKeyWrapper(context, DEFAULT_KEY_ALIAS, false);
            if (wrappedKeyString == null) {
                synchronized (DEFAULT_KEY_ALIAS.intern()) {
                    wrappedKeyString = sp.getString(DEFAULT_KEY_ALIAS, null);
                    if (wrappedKeyString == null) {
                        SecretKey secretKey = generateRandomKey();

                        byte[] wrapped = keyWrapper.wrap(secretKey);
                        wrappedKeyString = Base64.encode(wrapped);
                        sp.edit().putString(DEFAULT_KEY_ALIAS, wrappedKeyString).apply();
                        return secretKey;
                    }
                }
            }

            byte[] blob = Base64.decode(wrappedKeyString);
            SecretKey secretKey = keyWrapper.unwrap(blob);

            return secretKey;
        } catch (InvalidKeyException e) {
            throw new OMAuthenticationManagerException(OMErrorCode.KEY_UNWRAP_FAILED, e.getMessage(), e);
        } catch (Exception e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    public void removeKey() {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(context);
        sp.edit().remove(DEFAULT_KEY_ALIAS).apply();
    }

    /**
     * Random key.
     * @return
     * @throws NoSuchAlgorithmException
     */
    private SecretKey generateRandomKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        keyGenerator.init(new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }
}
