/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import android.content.Context;

import java.io.File;
import java.nio.charset.Charset;
import java.security.Key;

import oracle.idm.mobile.OMErrorCode;

/**
 * Provides an interface to creating and managing {@link OMKeyStore} objects.
 *
 */
public final class OMKeyManager {

    private static final String UTF8 = "UTF-8";
    private static final Charset UTF8_CHARSET = Charset.forName(UTF8);
    private final Context context;

    /**
     * Key support.
     */
    private final KeySupport keySupport = new KeySupport();

    /**
     * Serialization support.
     */
    private final SecureSerializationSupport secureSerializationSupport = new SecureSerializationSupport();

    private final FilePathSupport filePathSupport;

    /**
     * Default constructor.
     * @param context
     * @throws NullPointerException if passed context is null
     */
    public OMKeyManager(Context context) throws NullPointerException {
        if (context == null) {
            throw new NullPointerException("context cannot be null");
        }
        this.context = context;
        this.filePathSupport = new FilePathSupport(context);
    }

    /**
     * Returns the OMKeyStore for the given <code>keyStoreId</code> or throws exception if
     * there is no key store under the given key name. <br/>
     * Given <code>key</code> is used to decrypt the key store.
     *
     * @param keyStoreId id for the keystore
     * @param key key -- encoded as byte array -- used to encrypt/decrypt key store data
     * @return An OMKeyStore instance
     * @throws OMKeyManagerException if the key is invalid or key store with the given id doesn't exist
     * @throws NullPointerException if any of required parameters is null
     */
    public OMKeyStore getKeyStore(String keyStoreId, byte[] key) throws OMKeyManagerException, NullPointerException {
        if (keyStoreId == null) {
            throw new NullPointerException("keyStoreId");
        }

        if (key == null) {
            throw new NullPointerException("key");
        }

        if (key.length == 0) {
            throw new OMKeyManagerException(OMErrorCode.INVALID_INPUT, "0 length key");
        }

        File keyStoreFile = filePathSupport.getKeyStoreFile(keyStoreId);

        if (keyStoreFile == null || !keyStoreFile.exists()) {
            throw new OMKeyManagerException(OMErrorCode.KEYCHAIN_ITEM_NOT_FOUND, "No key store found with id [" + keyStoreId + "]");
        }

        Key internalKey = keySupport.getKeyFromBytes(key);
        OMKeyStore keyStore = new OMKeyStore(context, keyStoreId, internalKey);
        keyStore.loadSavedState();

        return keyStore;
    }


    /**
     * Creates a new key store under the given <code>keyStoreId</code> id. The given <code>encryptionKey</code>
     * is used to encrypt the newly created keystore.
     *
     * @param keyStoreId
     * @param encryptionKey key to encrypt. Only 128, 192 or 256 bits long keys are valid.
     * throws OMKeyManagerException if a key store with the given id already exists.
     * @return
     */
    public OMKeyStore createKeyStore(String keyStoreId, byte[] encryptionKey) throws OMKeyManagerException {
        File keyStoreFile = filePathSupport.getKeyStoreFile(keyStoreId);

        if (keyStoreFile != null && keyStoreFile.exists()) {
            throw new OMKeyManagerException(OMErrorCode.KEYCHAIN_ITEM_ALREADY_EXISTS, "A key store with id [" + keyStoreId + "] already exists.");
        }

        OMKeyStore keyStore = new OMKeyStore(context, keyStoreId, keySupport.getKeyFromBytes(encryptionKey));
        keyStore.createDefaultKey();
        keyStore.saveKeyStore();

        return keyStore;
    }


    /**
     * identifies keystore using keyStoreId, if not found then throws exception,
     * decrypts keystore and its data using currentEncKey and encrypts using newEncKey and returns updated OMKeyStore object.
     *
     * @param keyStoreId
     * @param currentKey
     * @param newKey
     * @return
     */
    public OMKeyStore updateEncryptionKey(String keyStoreId, byte[] currentKey, byte[] newKey)
            throws OMKeyManagerException {
        OMKeyStore keyStore = getKeyStore(keyStoreId, currentKey);
        if (keyStore == null) {
            throw new OMKeyManagerException(OMErrorCode.INVALID_INPUT, "Failed to load the key store with id [" + keyStoreId + "]. Bad decryption key?");
        }

        // change the encryption key and rewrite it disk...
        keyStore.updateKeyEncryptionKey(newKey);

        return keyStore;
    }

    /**
     * Deletes the underlying key store file for the given key store key if it exists, noop otherwise.
     * @param keyStoreId key store id.
     * @param key the key used to create this key store
     * @throws OMKeyManagerException if key is invalid or key store doesn't exist
     */
    public void deleteKeyStore(String keyStoreId, byte[] key) throws OMKeyManagerException {

        // we'll try to load the keystore...
        OMKeyStore keyStore = getKeyStore(keyStoreId, key);

        // now that we know that the given key can load given key store, we just delete it.
        keyStore.unloadKeys();

        File file = filePathSupport.getKeyStoreFile(keyStoreId);
        if (file.exists()) {
            file.delete();
        }
    }

}
