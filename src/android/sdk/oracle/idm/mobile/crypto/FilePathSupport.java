/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import android.content.Context;

import java.io.File;

/**
 * Kay manger and key store related file names and paths support.
 *
 */
public class FilePathSupport {

    private static final String KEY_STORE_FILE_SUFFIX = ".omks";
    public static final String DATA_FILE_SUFFIX = ".ss";

    private Context context;

    public FilePathSupport(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context cannot be null");
        }
        this.context = context;
    }

    /**
     * Loads the file for the given keystore id.
     *
     * @param keyStoreId
     * @return
     */
    public File getKeyStoreFile(String keyStoreId) throws OMKeyManagerException {
        if (keyStoreId == null) {
            throw new NullPointerException("keystoreId");
        }

        String filePath = getFilePathForKeyStoreId(keyStoreId);
        File file = new File(filePath);
        return file;
    }

    /**
     * Path for the key store file.
     * @param keyStoreId
     * @return
     */
    private String getFilePathForKeyStoreId(String keyStoreId) {
        return context.getFilesDir() + File.pathSeparator
                + getFileNameFromKeyStoreId(keyStoreId);
    }

    /**
     * This gives us a chance to cleanup keyStoreId to convert it to file name.
     *
     * @param keyStoreId
     * @return
     */
    private String getFileNameFromKeyStoreId(String keyStoreId) {
        String encoded = getFileNameFromId(keyStoreId);
        return encoded + KEY_STORE_FILE_SUFFIX;
    }

    /**
     * File for data id.
     * @param dataId
     * @return
     */
    public File getFileForDataId(String dataId) {

        if (dataId == null) {
            throw new NullPointerException("dataId");
        }

        File secureStorageDir = new File(context.getFilesDir(), "ss/");
        if (!secureStorageDir.exists()) {
            secureStorageDir.mkdir();
        }

        return new File(secureStorageDir, getFileNameForDataId(dataId));

    }

    /**
     * File name for given dat id. This is the only place where we convert <code>dataId</code>
     * into to a file name. We can, for example, replace spaces with underscores or have a
     * completely opaque scheme to convert dataId to file name; a MD5 hash for example.
     * @param dataId
     * @return
     */
    private String getFileNameForDataId(String dataId) {
        if (dataId == null) {
            return dataId;
        }

        String encoded = getFileNameFromId(dataId);

        return encoded + DATA_FILE_SUFFIX;
    }

    /**
     * Converts an id to file name.
     * @param id
     * @return
     */
    private String getFileNameFromId(String id) {
        String encoded = Base64.utfEncode(id);
        encoded = encoded.replaceAll("/", "z");
        return encoded;
    }

}
