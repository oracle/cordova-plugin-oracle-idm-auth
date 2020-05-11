/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import android.content.Context;

import java.io.File;
import java.io.Serializable;
import java.io.StreamCorruptedException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.logging.OMLog;

/**
 * Key store.
 */
public class OMKeyStore implements Serializable {

    private static final long serialVersionUID = -1455576501673848476L;
    private static final String TAG = OMKeyStore.class.getSimpleName();

    private static final String DEFAULT_KEY_ID = "__OMKeyStore_Default_Key";

    private transient Key encryptionKey;
    private final transient Context context;
    private final transient SecureSerializationSupport secureSerializationSupport = new SecureSerializationSupport();
    private final transient FilePathSupport filePathSupport;
    private final transient KeySupport keySupport = new KeySupport();
    private final transient String keyStoreId;

    /**
     * Only non-transient member for this class.
     */
    Map<String, byte[]> keys = new HashMap<>();

    /**
     * Only public constructor.
     *
     * @param keyStoreId id for this keystore
     */
    /* package */ OMKeyStore(Context context, String keyStoreId, Key encryptionKey) {
        if (context == null) {
            throw new IllegalArgumentException("context cannot be null");
        }

        this.context = context;
        this.keyStoreId = keyStoreId;
        this.encryptionKey = encryptionKey;
        this.filePathSupport = new FilePathSupport(context);
    }

    /* package */ void setEncryptionKey(Key encryptionKey) throws OMKeyManagerException {
        ensureValidState();
        this.encryptionKey = encryptionKey;
    }

    /**
     * Id for this key store.
     * @return
     */
    public String getKeyStoreId() throws OMKeyManagerException {
        ensureValidState();
        return keyStoreId;
    }

    /**
     * identifies key using key identifier, decrypts and return it.
     * This function is internal to SDK and client will not have access to it.
     * @param keyId
     * @return
     */
    /* package */ byte[] getKey(String keyId) throws OMKeyManagerException {
        if (keyId == null) {
            throw new NullPointerException("keyId");
        }
        ensureValidState();
        return keys.get(keyId);
    }

    /**
     * Unloads all keys from memory. Also removes encryption key from memory.
     * This function is internal to SDK and client will not have access to it.
     */
    /* package */ void unloadKeys() throws OMKeyManagerException {
        ensureValidState();
        Set<String> keySet = keys.keySet();
        for (String key : keySet) {
            keys.put(key, new byte[0]);
        }
        keys.clear();
        keys = null;
        this.encryptionKey = null;
    }

    /**
     * Checks to see if that {@link OMKeyStore#unloadKeys()} hasn't bee called to unload
     * the keys. If it has, would throw.
     * @throws OMKeyManagerException
     */
    private void ensureValidState() throws OMKeyManagerException {
        if (keys == null || encryptionKey == null) {
            throw new OMKeyManagerException(OMErrorCode.KEY_IS_NULL, "Invalid key store state. Already unloaded?");
        }
    }

    /**
     * Returns the 'default key' for this key store. A default key is just a random key generated
     * and stored at the time of key store creation.
     * @return key
     */
    public byte[] getDefaultKey() throws OMKeyManagerException {
        ensureValidState();
        byte[] defaultKey = getKey(DEFAULT_KEY_ID);
        if (OMSecurityConstants.DEBUG) {
            OMLog.trace(TAG, "**** DefaultKey = " + Base64.encode(defaultKey));
        }
        return defaultKey;
    }
    /**
     * Create a new random key under default key id.
     * See
     */
    /* package */ void createDefaultKey() throws OMKeyManagerException {
        if (keys.get(DEFAULT_KEY_ID) != null) {
            throw new OMKeyManagerException(OMErrorCode.KEYCHAIN_ITEM_ALREADY_EXISTS, "Default key already exists.");
        }
        createKey(DEFAULT_KEY_ID);
    }

    /**
     * See {@link OMKeyStore#createKey(String, boolean)}. This method passed <code>false</code>
     * for <code>replaceExisting</code> flag.
     * @param keyId
     * @return
     */
    public byte[] createKey(String keyId) throws OMKeyManagerException {
        ensureValidState();
        return createKey(keyId, false);
    }

    /**
     * Generates a random key and stores it under the given key identifier.
     * @param keyId
     * @param replaceExisting true if an existing key with the given id will be overwritten
     * @return
     */
    public byte[] createKey(String keyId, boolean replaceExisting) throws OMKeyManagerException {
        ensureValidState();
        if (!replaceExisting && keys.get(keyId) != null) {
            throw new OMKeyManagerException(OMErrorCode.KEYCHAIN_ITEM_ALREADY_EXISTS, "A key with id [" + keyId + "] already exists.");
        }
        Key key = createNewRandomKey();
        byte[] encodedKey = key.getEncoded();
        keys.put(keyId, encodedKey);
        if (OMSecurityConstants.DEBUG) {
            OMLog.trace(TAG, "****New key created. Key id: "+ keyId +
                    " Key Value: " + Base64.encode(encodedKey));
        }
        saveKeyStore();
        return encodedKey;
    }

    /**
     * Stores the given key store to disk after encrypting it.
     * @throws OMKeyManagerException
     * @throws NullPointerException if keyStoreId or output file is null
     */
    /* package */ void saveKeyStore() throws OMKeyManagerException, NullPointerException {

        ensureValidState();
        if (this.keyStoreId == null) {
            throw new NullPointerException("Cannot save key store with null id.");
        }

        File outputFile = filePathSupport.getKeyStoreFile(this.keyStoreId);
        if (outputFile == null) {
            throw new NullPointerException("Cannot save key store to a null file");
        }

        try {
            secureSerializationSupport.serialize(this, outputFile, this.encryptionKey);
        } catch (Exception e) {
            throw new OMKeyManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }

    }

    /**
     * Loads the serialized key store.
     * @return deserialized key store object
     * @throws OMKeyManagerException if given encryption is invalid
     * @throws NullPointerException if any of the state members required is null
     */
    OMKeyStore loadSavedState() throws OMKeyManagerException {

        if (this.keyStoreId == null) {
            throw new NullPointerException("keyStoreId");
        }

        if (this.encryptionKey == null) {
            throw new NullPointerException("encryptionKey");
        }

        try {
            File keyStoreFile = filePathSupport.getKeyStoreFile(this.keyStoreId);
            Serializable object = secureSerializationSupport.deserialize(keyStoreFile, this.encryptionKey);
            OMKeyStore loaded = (OMKeyStore) object;
            this.keys.clear();
            this.keys.putAll(loaded.keys);
            loaded.keys.clear();
            return this;
        } catch (StreamCorruptedException e) {
            throw new OMInvalidKeyException(OMErrorCode.INVALID_INPUT, e.getMessage(), e);
        }  catch (Exception e) {
            throw new OMKeyManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    /**
     * For each key id in keyIds, generates a random key.
     * @param keyIds
     */
    public void createKeys(List<String> keyIds) throws OMKeyManagerException {
        ensureValidState();
        for (String keyId : keyIds) {
            createKey(keyId);
        }
    }

    /**
     * Actual method to do the heavy lifting for creating a new random key.
     * @return
     */
    private Key createNewRandomKey() throws OMKeyManagerException {
        ensureValidState();
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            throw new OMKeyManagerException(OMErrorCode.UNKNOWN_OR_UNSUPPORTED_ALGORITHM, e.getMessage(), e);
        }
    }


    /**
     * deletes key identified as keyId. This function is public to SDK and client will have access to it.
     * @param keyId
     */
    public void deleteKey(String keyId) throws OMKeyManagerException {
        ensureValidState();
        byte[] removed = keys.remove(keyId);
        if (removed != null) {
            saveKeyStore();
        }
    }

    /**
     * Decrypts all the keys using internally stored encryption key and encrypts them again
     * using the given <code>newEncryptionKey</code> key.
     * Basically this function will be used to re-encrypts all keys using new encryption key.
     *
     * @param newEncryptionKey
     *
     */
    /* package */ void updateKeyEncryptionKey(byte[] newEncryptionKey) throws OMKeyManagerException {
        ensureValidState();
        this.encryptionKey = keySupport.getKeyFromBytes(newEncryptionKey);
        saveKeyStore();
    }

    /**
     * Copies the keys from keystore provided as argument to this keystore
     *
     * @param keyStore
     * @throws OMKeyManagerException
     */
    public void copyKeysFrom(OMKeyStore keyStore) throws OMKeyManagerException {
        if (keyStore == null) {
            throw new NullPointerException("keyStore");
        }
        ensureValidState();
        for (Map.Entry<String, byte[]> entry : keyStore.keys.entrySet()) {
            keys.put(entry.getKey(), entry.getValue());
        }
        if (OMSecurityConstants.DEBUG) {
            for (Map.Entry<String, byte[]> entry : keyStore.keys.entrySet()) {
                OMLog.trace(TAG, "****Key copied. Key id : " + entry.getKey() +
                        " Key Value: " + Base64.encode(entry.getValue()));
            }
        }
        saveKeyStore();
    }
}
