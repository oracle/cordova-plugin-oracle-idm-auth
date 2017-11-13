/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import android.content.Context;

import java.io.File;
import java.io.Serializable;
import java.security.Key;

import oracle.idm.mobile.OMErrorCode;

/**
 * Secure storage.
 */
public class OMSecureStorageService {

    private final Context context;
    private final OMKeyStore keyStore;
    private final String keyId;

    private final KeySupport keySupport = new KeySupport();
    private final SecureSerializationSupport secureSerializationSupport = new SecureSerializationSupport();
    private final FilePathSupport filePathSupport;

    /**
     * Initializes OMSecureStorageService instance with OMKeyStore instance.
     * @param context
     * @param keyStore
     * @param keyId
     * @throws NullPointerException if any of the inputs is null
     */
    public OMSecureStorageService(Context context, OMKeyStore keyStore, String keyId) throws NullPointerException {
        if (context == null) {
            throw new NullPointerException("Context cannot be null");
        }
        this.context = context;

        if (keyStore == null) {
            throw new NullPointerException("Key store cannot be null");
        }
        this.keyStore = keyStore;

        if (keyId == null) {
            throw new NullPointerException("Key id cannot be null");
        }
        this.keyId = keyId;

        this.filePathSupport = new FilePathSupport(context);
    }

    private Key getKey() throws OMKeyManagerException {
        return keySupport.getKeyFromBytes(this.keyStore.getKey(keyId));
    }

    /**
     * Returns data for specific dataId from secure storage or null if there is no data stored
     * under the given dataId.
     *
     * @param dataId
     * @throws NullPointerException if the input parameter is null
     * @throws OMSecureStorageException any exceptions thrown by underlying IO system
     * @return
     */
    public Serializable get(String dataId) throws OMSecureStorageException, NullPointerException {
        if (dataId == null) {
            throw new NullPointerException("data id/key cannot be null");
        }

        File file = filePathSupport.getFileForDataId(dataId);
        if (file == null || !file.exists()) {
            return null;
        }

        try {
            return secureSerializationSupport.deserialize(file, getKey());
        } catch (Exception e) {
            throw new OMSecureStorageException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }


    /**
     * Stores data for specific dataId in secure storage. If we already have data stored under
     * the given id, it would be overwritten.
     * @param dataId the id under with the given data would be stored
     * @param data
     */
    public void store(String dataId, Serializable data) throws OMSecureStorageException, NullPointerException {
        if (dataId == null) {
            throw new NullPointerException("data id/key cannot be null");
        }

        if (data == null) {
            throw new NullPointerException("data cannot be null");
        }

        try {
            secureSerializationSupport.serialize(data, filePathSupport.getFileForDataId(dataId), getKey());
        } catch (Exception e) {
            throw new OMSecureStorageException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }

    }


    /**
     * Deletes data for specific dataId in secure storage.
     * @param dataId
     */
    public void delete(String dataId) {
        File file = filePathSupport.getFileForDataId(dataId);
        if (file != null && file.exists()) {
            file.delete();
        }
    }

}
