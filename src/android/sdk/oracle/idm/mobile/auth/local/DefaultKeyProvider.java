/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

import oracle.idm.mobile.OMErrorCode;

/**
 * Default key provider with a random key generator.
 */
public class DefaultKeyProvider implements KeyProvider {
    public static final String INSTALLATION_ID = "installation_id";

    private static final String TAG = DefaultKeyProvider.class.getSimpleName();

    private Context context;

    public DefaultKeyProvider(Context context) {
        this.context = context;
    }

    @Override
    public Key getKey() throws OMAuthenticationManagerException {
        String installationId = getInstallationId();
        return new SecretKeySpec(hash(installationId), "AES");
    }

    private String getInstallationId() {
        String androidId = Settings.Secure.getString(context.getContentResolver(),
                Settings.Secure.ANDROID_ID);

        if (androidId == null) {
            SharedPreferences sp = context.getSharedPreferences(DefaultKeyProvider.class.getName(),
                    Context.MODE_PRIVATE);
            String storedInstallationId = sp.getString(INSTALLATION_ID, null);
            if (storedInstallationId == null) {
                synchronized (DefaultKeyProvider.class) {
                    storedInstallationId = sp.getString(INSTALLATION_ID, null);
                    if (storedInstallationId == null) {
                        UUID uuid = UUID.randomUUID();
                        sp.edit().putString(INSTALLATION_ID, uuid.toString()).commit();
                        return uuid.toString();        
                    }
                }    
            }
            return storedInstallationId;
        }

        return androidId;
    }

    private byte[] hash(String s) throws OMAuthenticationManagerException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(s.getBytes(Charset.forName("UTF-8")));

        } catch (NoSuchAlgorithmException e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }

    }
}
