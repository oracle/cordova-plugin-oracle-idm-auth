/*
 * Copyright (c) 2019, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.credentialstore;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.text.TextUtils;

import static oracle.idm.mobile.OMSecurityConstants.OM_CREDENTIAL;

/**
 * OMCredentialStore is storage class which stores all the data that needs
 * persistent storage using the {@link SharedPreferences}.
 * <p>
 * This is added only for the purpose of reading {@link OMCredential}
 * from its string representation format used by Headed SDK.
 */
public class OMClassicCredentialStore {
    private Context context;

    /**
     * Constructor of credential store
     *
     * @param context reference to the current context instance.
     */
    public OMClassicCredentialStore(Context context) {
        this.context = context;
    }

    /**
     * Gets an {@link OMCredential} instance if the given key contains a valid
     * value stored in the preferences store.
     *
     * @param key key to be used for searching in the credential store.
     * @return an instance of {@link OMCredential}
     */
    public OMCredential getCredential(String key) {
        OMCredential credential = null;
        String credentialStr;
        SharedPreferences preferences = getPreference();
        if (!TextUtils.isEmpty(key)) {
            key = key + OM_CREDENTIAL;
            credentialStr = preferences.getString(key, null);

            if (credentialStr != null) {
                credential = new OMCredential(credentialStr, true);
            }

        }
        return credential;
    }

    /**
     * Deletes the credential information that is stored against the given key
     * in the credential store.
     *
     * @param key key to be used for deletion.
     */
    public void deleteCredential(String key) {
        if (key != null) {
            key = key + OM_CREDENTIAL;
            remove(key);
        }
    }

    /**
     * This is to delete a value stored against a given key from the shared
     * preference. In order to delete credential,
     * {@link OMCredentialStore#deleteCredential(String)} should be used instead
     * of this method.
     *
     * @param keyName name of the key to be removed
     */
    public void remove(String keyName) {
        SharedPreferences preferences = getPreference();
        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(keyName);
        editor.commit();
    }

    /**
     * Gets the shared preference instance.
     *
     * @return {@link SharedPreferences}
     */
    private SharedPreferences getPreference() {
        return PreferenceManager.getDefaultSharedPreferences(context);
    }
}
