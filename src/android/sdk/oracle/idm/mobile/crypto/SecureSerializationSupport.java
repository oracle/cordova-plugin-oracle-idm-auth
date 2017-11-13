/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import oracle.idm.mobile.OMErrorCode;

/**
 * Common reusable code for secure
 *
 */
/* package */ final class SecureSerializationSupport {

    public static final String AES_TRANSFORMATION = "AES/CBC/PKCS7Padding";
    public static final int IV_LENGTH = 16;

    /**
     * We don't liked to be instantiated outside our package.
     */
    /* package */ SecureSerializationSupport() {
    }

    /**
     * Deserializes an object from the given file that was written
     * using {@link SecureSerializationSupport#serialize(Serializable, File, Key)} method.
     * @param inputFile
     * @param decryptionKey
     * @return
     * @throws Exception
     */
    public Serializable deserialize(File inputFile, Key decryptionKey) throws Exception {
        FileInputStream fis = null;
        ObjectInputStream ois = null;

        try {
            fis = new FileInputStream(inputFile);

            // read the IV and hence move the fp to actual encrypted data
            byte[] iv = new byte[SecureSerializationSupport.IV_LENGTH];
            int read = fis.read(iv);
            if (read != SecureSerializationSupport.IV_LENGTH) {
                throw new OMKeyManagerException(OMErrorCode.IV_LENGTH_MUST_MATCH_ALGORITHM_BLOCK_SIZE,
                        "Failed to read IV header from serialized file");
            }

            final IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = getDecryptingCipher(decryptionKey, ivSpec);

            ois = new ObjectInputStream(new CipherInputStream(fis, cipher));
            Object object = ois.readObject();
            return (Serializable) object;
        } finally {
            closeQuietly(ois);
            closeQuietly(fis);
        }
    }

    /**
     * Writes an object to the given file after encrypting it the with the given key.
     * @param data
     * @param destFile
     * @param encryptionKey
     * @throws Exception mainly IOException
     */
    public void serialize(Serializable data, File destFile, Key encryptionKey) throws Exception {
        FileOutputStream fos = null;
        ObjectOutputStream oos = null;
        try {
            fos = new FileOutputStream(destFile);

            final IvParameterSpec iv = getRandomIv();
            Cipher cipher = getEncryptingCipher(encryptionKey, iv);

            // write unencrypted IV as the header
            fos.write(iv.getIV());

            oos = new ObjectOutputStream(new CipherOutputStream(fos, cipher));
            oos.writeObject(data);
        } finally {
            closeQuietly(oos);
            closeQuietly(fos);
        }
    }

    /**
     * Tries to close any <code>Closeable</code> object if it's non-null ignoring any exceptions.
     * @param closeable
     */
    private void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignored) {}
        }
    }

    /**
     * Write a given <code>Serializable</code> to byte array and return the array.
     * @param serializable
     * @return
     */
    public byte[] serializableToByteArray(Serializable serializable) throws OMKeyManagerException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = null;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(serializable);
            byte[] bytes = bos.toByteArray();
            return bytes;
        } catch (IOException e) {
            throw new OMKeyManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        } finally {
            closeQuietly(out);
        }
    }

    /**
     * Decrypt cipher.
     * @param key
     * @param iv
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public Cipher getDecryptingCipher(Key key, IvParameterSpec iv) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher;
    }

    /**
     * Encrypting cipher.
     * @param key
     * @param iv
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public Cipher getEncryptingCipher(Key key, IvParameterSpec iv) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher;
    }

    /**
     * Generates a random IV.
     * @return
     */
    public IvParameterSpec getRandomIv() {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        sr.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
