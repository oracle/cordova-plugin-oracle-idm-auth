/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.certificate;

/**
 * Class to hold the preference of client certificate to be used
 *
 * @hide // if other platforms are OK, make this un hidden.
 * Created by ajulka on 2/24/2016.
 */
public class ClientCertificatePreference {

    public enum Storage {
        /**
         * Specifies to use AndroidKeyStore (introduced in Android 4.3) for storing
         * client certificate credentials. This has the security feature of
         * "Extraction Prevention" as mentioned in
         * https://developer.android.com/training/articles/keystore.html.
         *
         * <br />
         * Note: The keys in Android Keystore will be deleted in certain scenarios
         * like changing the secure lock screen from Swipe -> Pattern. This is due
         * to an android bug:
         * https://code.google.com/p/android/issues/detail?id=61989
         *
         */
        APP_LEVEL_ANDROID_KEYSTORE,
        /**
         * Specifies to use application local {@link java.security.KeyStore} for storing client certificate credentials.
         * The type of keystore created is based on the type returned by {@link java.security.KeyStore#getDefaultType()}.<br />
         * Note: This is not secure on a rooted device. For better security, use
         * {@link Storage#APP_LEVEL_ANDROID_KEYSTORE}.
         */
        APP_LEVEL_KEYSTORE,
        /**
         * Specifies to use Android system {@link android.security.KeyChain} for storing client certificate
         * credentials.
         */
        SYSTEM_LEVEL_KEYSTORE
    }

    private static String TAG = ClientCertificatePreference.class.getSimpleName();
    private String mAlias;
    //default storage preference
    private Storage mStorage = Storage.APP_LEVEL_KEYSTORE;

    public ClientCertificatePreference(String alias) {
        mAlias = alias;
    }

    public ClientCertificatePreference(String alias, Storage storage) {
        this(alias);
        mStorage = storage;
    }


    public void setAlias(String alias) {
        mAlias = alias;
    }

    public void setStorage(Storage store) {
        mStorage = store;
    }

    public String getAlias() {
        return mAlias;
    }

    public Storage

    getStorage() {
        return mStorage;
    }
}
