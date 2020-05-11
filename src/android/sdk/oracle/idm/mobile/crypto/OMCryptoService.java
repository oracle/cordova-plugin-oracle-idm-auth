/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import android.util.Log;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.util.ArrayUtils;

/**
 * OMCryptoService class is to perform hashing / encrption / decryption of plain
 * text. It also provides method to compare a plain text with an encoded text.
 */
public class OMCryptoService {
    private static final String TAG = OMCryptoService.class.getName();
    private static final String ENCRYPTION_KEY = "SDKEncryptionKey";
    private static final int ENCRYPTION_KEY_BYTE_LENGTH = 16;
    private static final SecureRandom secureRandom = new SecureRandom();
    private byte[] encryptionKey;
    private OMCredentialStore credStore;

    public OMCryptoService(OMCredentialStore credStore) {
        if (credStore == null) {
            throw new IllegalArgumentException("OMCredentialStore must be non-null");
        }
        this.credStore = credStore;
    }

    /**
     * Produces a hashed form (Base64 encoded form of salted bytes followed by
     * hash bytes) of the plain text based on the given {@link CryptoScheme}
     * algorithm. If the given {@link CryptoScheme} algorithm doesn't belong to
     * any valid java crypto hash algorithm, then it throws an
     * {@link IllegalArgumentException}. This method will also throw
     * {@link IllegalArgumentException} if the plain text is empty or null. It
     * will throw {@link CryptoException} if it encounters any exception in the
     * process of hashing. If the given {@link CryptoScheme} algorithm is a
     * salted one and the salt length is not specified, then the default is 8
     * bytes.
     *
     * @param plainText       text to be hashed
     * @param scheme          algorithm to be used for hashing
     * @param saltLength      number of bytes in the salt
     * @param prefixAlgorithm whether the hashing algorithm name should be prefixed in the
     *                        result as {algorithm name}
     * @return hashed text
     * @throws CryptoException          if there is any exception in the process of hashing
     * @throws IllegalArgumentException If the given plain text is null or empty If the algorithm
     *                                  specified is not an hashing algorithm.
     * @deprecated Normally passwords are hashed. Hence, plainText given here can be password.
     * Storing password in String as opposed to char[] is a security concern. So, instead of this
     * method, use {@link #hash(byte[], CryptoScheme, int, byte[], boolean)} .
     */
    @Deprecated
    public String hash(String plainText, CryptoScheme scheme, int saltLength,
                       boolean prefixAlgorithm) throws CryptoException {
        return hash(plainText, scheme, saltLength, null, prefixAlgorithm);
    }

    /**
     * Produces a hashed form (salted bytes followed by hash bytes) of the plain
     * text based on the given {@link CryptoScheme} algorithm. If the given
     * {@link CryptoScheme} algorithm doesn't belong to any valid java crypto
     * hash algorithm, then it throws an {@link IllegalArgumentException}. The
     * hashed bytes returned are not Base64 encoded .This method will also throw
     * {@link IllegalArgumentException} if the plain text is empty or null. It
     * will throw {@link CryptoException} if it encounters any exception in the
     * process of hashing. If the given {@link CryptoScheme} algorithm is a
     * salted one and the salt length is not specified, then the default is 8
     * bytes.
     *
     * @param plainText  text to be hashed
     * @param scheme     algorithm to be used for hashing
     * @param saltLength number of bytes in the salt
     * @return hashed plain text as byte array
     * @throws CryptoException
     */

    public byte[] hash(String plainText, CryptoScheme scheme, int saltLength)
            throws CryptoException {
        byte[] hashedBytes = null;
        hashedBytes = hash(plainText, scheme, saltLength, null);
        return hashedBytes;
    }

    /**
     * Produces a hashed form (Base64 encoded form of salted bytes followed by
     * hash bytes) of the plain text based on the given {@link CryptoScheme}
     * algorithm. If the given {@link CryptoScheme} algorithm doesn't belong to
     * any valid java crypto hash algorithm, then it throws an
     * {@link IllegalArgumentException}. This method will also throw
     * {@link IllegalArgumentException} if the plain text is empty or null. It
     * will throw {@link CryptoException} if it encounters any exception in the
     * process of hashing. If the given {@link CryptoScheme} algorithm is a
     * salted one and the salt length is not specified, then the default is 8
     * bytes.  If the salt bytes are not specified, a random salt will be
     * generated of {@code saltLength} bits.
     *
     * @param plainText       text to be hashed
     * @param scheme          algorithm to be used for hashing
     * @param saltLength      number of bytes in the salt
     * @param salt            array of bytes to be used as the salt
     * @param prefixAlgorithm whether the hashing algorithm name should be prefixed in the
     *                        result as {algorithm name}
     * @return hashed text
     * @throws CryptoException          if there is any exception in the process of hashing
     * @throws IllegalArgumentException If the given plain text is null or empty If the algorithm
     *                                  specified is not an hashing algorithm.
     * @deprecated Normally passwords are hashed. Hence, plainText given here can be password.
     * Storing password in String as opposed to char[] is a security concern. So, instead of this
     * method, use {@link #hash(byte[], CryptoScheme, int, byte[], boolean)}
     */
    @Deprecated
    public String hash(String plainText, CryptoScheme scheme, int saltLength,
                       byte[] salt, boolean prefixAlgorithm) throws CryptoException {
        if (plainText == null || plainText.length() == 0) {
            throw new IllegalArgumentException(
                    "Text for hashing cannot be null or empty.");
        }
        return hash(plainText.getBytes(Charset.forName(OMSecurityConstants.UTF_8)), scheme, saltLength,
                salt, prefixAlgorithm);
    }

    /**
     * Produces a hashed form (Base64 encoded form of salted bytes followed by
     * hash bytes) of the plain text based on the given {@link CryptoScheme}
     * algorithm. If the given {@link CryptoScheme} algorithm doesn't belong to
     * any valid java crypto hash algorithm, then it throws an
     * {@link IllegalArgumentException}. This method will also throw
     * {@link IllegalArgumentException} if the plain text is empty or null. It
     * will throw {@link CryptoException} if it encounters any exception in the
     * process of hashing. If the given {@link CryptoScheme} algorithm is a
     * salted one and the salt length is not specified, then the default is 8
     * bytes.  If the salt bytes are not specified, a random salt will be
     * generated of {@code saltLength} bits.
     *
     * @param plainText       text to be hashed
     * @param scheme          algorithm to be used for hashing
     * @param saltLength      number of bytes in the salt
     * @param salt            array of bytes to be used as the salt
     * @param prefixAlgorithm whether the hashing algorithm name should be prefixed in the
     *                        result as {algorithm name}
     * @return hashed text
     * @throws CryptoException          if there is any exception in the process of hashing
     * @throws IllegalArgumentException If the given plain text is null or empty If the algorithm
     *                                  specified is not an hashing algorithm.
     */
    public String hash(byte[] plainText, CryptoScheme scheme, int saltLength,
                       byte[] salt, boolean prefixAlgorithm) throws CryptoException {
        String hashText = null;
        byte[] digestWithSalt = null;
        digestWithSalt = hash(plainText, scheme, saltLength, salt);

        hashText = Base64.encode(digestWithSalt);

        if (prefixAlgorithm) {
            hashText = prefixAlgorithm(scheme, hashText);
        }

        return hashText;
    }

    /**
     * Produces a hashed form (salted bytes followed by hash bytes) of the plain
     * text based on the given {@link CryptoScheme} algorithm. If the given
     * {@link CryptoScheme} algorithm doesn't belong to any valid java crypto
     * hash algorithm, then it throws an {@link IllegalArgumentException}. The
     * hashed bytes returned are not Base64 encoded .This method will also throw
     * {@link IllegalArgumentException} if the plain text is empty or null. It
     * will throw {@link CryptoException} if it encounters any exception in the
     * process of hashing. If the given {@link CryptoScheme} algorithm is a
     * salted one and the salt bit length is not specified, then the default is
     * 8 bytes. If the salt bytes are not specified, a random salt will be
     * generated of {@code saltLength} bits.
     *
     * @param plainText  text to be hashed
     * @param scheme     algorithm to be used for hashing
     * @param saltLength number of bytes in the salt
     * @param salt       array of bytes to be used as the salt
     * @return hashed plain text as byte array
     * @throws CryptoException          if there is any exception in the process of hashing
     * @throws IllegalArgumentException If the given plain text is null or empty. If the algorithm
     *                                  specified is not an hashing algorithm.
     */

    public byte[] hash(byte[] plainText, CryptoScheme scheme, int saltLength,
                       byte[] salt) throws CryptoException {
        if (plainText == null || plainText.length == 0) {
            throw new IllegalArgumentException(
                    "Text for hashing cannot be null or empty.");
        }

        if (scheme == null || !CryptoScheme.isHashAlgorithm(scheme)) {
            throw new IllegalArgumentException("Invalid hash algorithm.");
        }

        if (CryptoScheme.isSaltedHashAlgorithm(scheme) && saltLength <= 0) {
            throw new IllegalArgumentException(
                    "Salt length should be greater than zero.");
        }

        try {
            String schemeValue = scheme.getValue();
            boolean isSalted = CryptoScheme.isSaltedHashAlgorithm(scheme);
            if (isSalted) {
                /* 6 corresponds to index after "Salted" in "SaltedSHA-xxx" */
                schemeValue = schemeValue.substring(6);
            }
            MessageDigest md = MessageDigest.getInstance(schemeValue);
            md.update(plainText); // first is the plainText

            if (isSalted) {
                if (salt == null || salt.length != saltLength) {
                    salt = new byte[saltLength];
                    secureRandom.nextBytes(salt);
                }
                md.update(salt); // second is the salt value
            }
            byte[] digest = md.digest(); // obtaining the digest bytes
            byte[] digestWithSalt = null;
            if (isSalted) {
                digestWithSalt = new byte[digest.length + salt.length];
                System.arraycopy(digest, 0, digestWithSalt, 0, digest.length);
                System.arraycopy(salt, 0, digestWithSalt, digest.length,
                        salt.length);
            } else {
                digestWithSalt = digest;
            }
            return digestWithSalt;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Produces a hashed form (salted bytes followed by hash bytes) of the plain
     * text based on the given {@link CryptoScheme} algorithm. If the given
     * {@link CryptoScheme} algorithm doesn't belong to any valid java crypto
     * hash algorithm, then it throws an {@link IllegalArgumentException}. The
     * hashed bytes returned are not Base64 encoded .This method will also throw
     * {@link IllegalArgumentException} if the plain text is empty or null. It
     * will throw {@link CryptoException} if it encounters any exception in the
     * process of hashing. If the given {@link CryptoScheme} algorithm is a
     * salted one and the salt bit length is not specified, then the default is
     * 8 bytes. If the salt bytes are not specified, a random salt will be
     * generated of {@code saltLength} bits.
     *
     * @param plainText  text to be hashed
     * @param scheme     algorithm to be used for hashing
     * @param saltLength number of bytes in the salt
     * @param salt       array of bytes to be used as the salt
     * @return hashed plain text as byte array
     * @throws CryptoException          if there is any exception in the process of hashing
     * @throws IllegalArgumentException If the given plain text is null or empty. If the algorithm
     *                                  specified is not an hashing algorithm.
     * @deprecated Normally passwords are hashed. Hence, plainText given here can be password.
     * Storing password in String as opposed to char[] is a security concern. So, instead of this
     * method, use {@link #hash(byte[], CryptoScheme, int, byte[])} .
     */
    @Deprecated
    public byte[] hash(String plainText, CryptoScheme scheme, int saltLength,
                       byte[] salt) throws CryptoException {
        if (plainText == null || plainText.length() == 0) {
            throw new IllegalArgumentException(
                    "Text for hashing cannot be null or empty.");
        }

        return hash(plainText.getBytes(Charset.forName("UTF-8")), scheme, saltLength, salt);
    }

    /**
     * Produces an encrypted text of the given plain text based on the
     * encryption algorithm given in the {@link CryptoScheme} instance. Note
     * that this does not prefix the encrypted text with the initialization
     * vector.
     *
     * @param plainText            text be to encrypted
     * @param scheme               encryption algorithm
     * @param mode                 mode for the encryption algorithm. This can be supplied with a
     *                             null value, in this case it will use the default mode
     *                             supported by the underlying java cryptography specification.
     * @param padding              padding for the encryption algorithm. This can be supplied
     *                             with a null value, in this case it will use the default
     *                             padding supported by the underlying java cryptography
     *                             specification. If the padding supplied is "NoPadding", make
     *                             sure that the size of plainText is a multiple of the block
     *                             size (AES: 128 bits; DES: 64 bits), otherwise CryptoException
     *                             will be thrown.
     * @param prefixAlgorithm      should the algorithm name should be prefix or not
     * @param key                  key used to encrypt .
     * @param initializationVector the initialization vector to be used for encryption
     * @return encrypted text
     * @throws CryptoException          if any exception occurred in the process of encryption
     * @throws IllegalArgumentException If the given plain text is null or empty, If the padding is
     *                                  not valid for the given algorithm, If the algorithm chosen is
     *                                  not an encryption algorithm
     * @see <a
     * href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher">Crypto
     * Modes & Padding</a>
     */
    public String encrypt(String plainText, CryptoScheme scheme, String mode,
                          String padding, boolean prefixAlgorithm, byte[] key,
                          byte[] initializationVector) throws CryptoException {
        if (plainText == null || plainText.length() == 0) {
            throw new IllegalArgumentException(
                    "Text for encryption cannot be null or empty.");
        }

        if (initializationVector == null || initializationVector.length == 0) {
            throw new IllegalArgumentException(
                    "Initialization vector cannot be null or empty.");
        }

        String encrypt = null;
        try {
            Cipher cipher = getCipher(scheme, mode, padding, null, true, key,
                    initializationVector);
            byte[] encryptedText = cipher.doFinal(plainText.getBytes());

            encrypt = Base64.encode(encryptedText);

            if (prefixAlgorithm) {
                encrypt = prefixAlgorithm(
                        getCipherTransformation(scheme, mode, padding), encrypt);
            }
        } catch (Exception e) {
            throw new CryptoException(e);
        }

        return encrypt;
    }


    /**
     * This method prefixs the given algorithm to the text and returns the
     * result as "{algorihthm}text".
     *
     * @param scheme scheme to be prefixed
     * @param text   text value
     * @return string value prefixing the algorithm to the text.
     * @deprecated text given can be password. So, use {@link #prefixAlgorithm(CryptoScheme, char[])}.
     */
    @Deprecated
    public String prefixAlgorithm(CryptoScheme scheme, String text) {
        if (text == null || text.length() == 0) {
            throw new IllegalArgumentException(
                    "Text cannot be null or an empty string");
        }

        return new String(prefixAlgorithm(scheme, text.toCharArray()));
    }

    /**
     * This method prefixs the given algorithm to the text and returns the
     * result as "{algorihthm}text".
     *
     * @param scheme scheme to be prefixed
     * @param text   text value
     * @return string value prefixing the algorithm to the text.
     */
    public char[] prefixAlgorithm(CryptoScheme scheme, char[] text) {
        if (text == null || text.length == 0) {
            throw new IllegalArgumentException(
                    "Text cannot be null or an empty string");
        }

        StringBuilder sb = new StringBuilder("{");
        sb.append(scheme.getValue()).append('}').append(text);
        char[] result = new char[sb.length()];
        sb.getChars(0, sb.length(), result, 0);
        return result;
    }

    @Deprecated
    public String encrypt(String plainText, CryptoScheme scheme, String mode,
                          String padding, boolean prefixAlgorithm) throws CryptoException {
        if (plainText == null || plainText.length() == 0) {
            throw new IllegalArgumentException(
                    "Text for encryption cannot be null or empty.");
        }

        String encrypt = null;
        try {
            Cipher cipher = getCipher(scheme, mode, padding, null, true, null,
                    null);
            byte[] encryptedText = cipher.doFinal(plainText.getBytes());

            int blockSize = cipher.getBlockSize();
            byte[] ivEnc = new byte[blockSize + encryptedText.length];

            /*
             * Android 4.3 uses OpenSSl provider which may return an non null iv
             * but with size 0 which causes ArrayIndexOutOfBoundsException
             */
            if (cipher.getIV() != null && cipher.getIV().length > 0) {
                System.arraycopy(cipher.getIV(), 0, ivEnc, 0, blockSize);
            }
            System.arraycopy(encryptedText, 0, ivEnc, blockSize,
                    encryptedText.length);

            encrypt = Base64.encode(ivEnc);

            if (prefixAlgorithm) {
                encrypt = prefixAlgorithm(
                        getCipherTransformation(scheme, mode, padding), encrypt);
            }
        } catch (Exception e) {
            throw new CryptoException(e);
        }

        return encrypt;
    }

    /**
     * Produces a encrypted text of the given plain text based on the encryption
     * algorithm given in the {@link CryptoScheme} instance.
     *
     * @param plainText       text be to encrypted
     * @param scheme          encryption algorithm
     * @param mode            mode for the encryption algorithm. This can be supplied with a
     *                        null value, in this case it will use the default mode
     *                        supported by the underlying java cryptography specification.
     * @param padding         padding for the encryption algorithm. This can be supplied
     *                        with a null value, in this case it will use the default
     *                        padding supported by the underlying java cryptography
     *                        specification. If the padding supplied is "NoPadding", make
     *                        sure that the size of plainText is a multiple of the block
     *                        size (AES: 128 bits; DES: 64 bits), otherwise CryptoException
     *                        will be thrown.
     * @param prefixAlgorithm should the algorithm name should be prefix or not
     * @param key             key used to encrypt .
     * @return encrypted text
     * @throws CryptoException          if any exception occurred in the process of encryption
     * @throws IllegalArgumentException If the given plain text is null or empty, If the padding is
     *                                  not valid for the given algorithm, If the algorithm chosen is
     *                                  not an encryption algorithm
     * @see <a
     * href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher">Crypto
     * Modes & Padding</a>
     */
    public String encrypt(String plainText, CryptoScheme scheme, String mode,
                          String padding, boolean prefixAlgorithm, byte[] key)
            throws CryptoException {
        if (plainText == null || plainText.length() == 0) {
            throw new IllegalArgumentException(
                    "Text for encryption cannot be null or empty.");
        }

        String encrypt = null;
        try {
            Cipher cipher = getCipher(scheme, mode, padding, null, true, key,
                    null);
            byte[] encryptedText = cipher.doFinal(plainText.getBytes());

            int blockSize = cipher.getBlockSize();
            byte[] ivEnc = new byte[blockSize + encryptedText.length];

            /*
             * Android 4.3 uses OpenSSl provider which may return an non null iv
             * but with size 0 which causes ArrayIndexOutOfBoundsException
             */
            if (cipher.getIV() != null && cipher.getIV().length > 0) {
                System.arraycopy(cipher.getIV(), 0, ivEnc, 0, blockSize);
            }
            System.arraycopy(encryptedText, 0, ivEnc, blockSize,
                    encryptedText.length);

            encrypt = Base64.encode(ivEnc);

            if (prefixAlgorithm) {
                encrypt = prefixAlgorithm(
                        getCipherTransformation(scheme, mode, padding), encrypt);
            }
        } catch (Exception e) {
            throw new CryptoException(e);
        }

        return encrypt;
    }

    /**
     * Gets a de-crypted plain text for the given encrypted input text.
     *
     * @param encryptedText text to be de-crypted
     * @param scheme        encryption algorithm
     * @param mode          mode for the encryption algorithm
     * @param padding       padding for the encryption algorithm
     * @param key           key used to decrypt .
     * @return plain text
     * @throws CryptoException          if any exception occurred in the process of encryption
     * @throws IllegalArgumentException If the input text is empty or null
     */
    public String decrypt(String encryptedText, CryptoScheme scheme,
                          String mode, String padding, byte[] key) throws CryptoException {
        if (encryptedText == null || encryptedText.length() == 0) {
            throw new IllegalArgumentException(
                    "Encrypted text cannot be null or empty.");
        }

        String decrypt = null;
        try {
            byte[] encryptedBytes = Base64.decode(encryptedText);
            Cipher cipher = getCipher(scheme, mode, padding, encryptedBytes,
                    false, key, null);
            int blockSize = cipher.getBlockSize();
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes, blockSize,
                    (encryptedBytes.length - blockSize));

            decrypt = new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return decrypt;
    }

    /**
     * Gets a decrypted plain text for the given encrypted input text. Note that
     * this does not presume that the encrypted text is prefixed with the
     * initialization vector.
     *
     * @param encryptedText        text to be de-crypted
     * @param scheme               encryption algorithm
     * @param mode                 mode for the encryption algorithm
     * @param padding              padding for the encryption algorithm
     * @param key                  key used to decrypt.
     * @param initializationVector the initialization vector to be used for decryption. This
     *                             should be same as the one supplied during encryption.
     * @return plain text
     * @throws CryptoException          if any exception occurred in the process of encryption
     * @throws IllegalArgumentException If the input text is empty or null
     */
    public String decrypt(String encryptedText, CryptoScheme scheme,
                          String mode, String padding, byte[] key, byte[] initializationVector)
            throws CryptoException {
        if (encryptedText == null || encryptedText.length() == 0) {
            throw new IllegalArgumentException(
                    "Encrypted text cannot be null or empty.");
        }

        if (initializationVector == null || initializationVector.length == 0) {
            throw new IllegalArgumentException(
                    "Initialization vector cannot be null or empty.");
        }

        String decrypt = null;
        try {
            byte[] encryptedBytes = Base64.decode(encryptedText);
            Cipher cipher = getCipher(scheme, mode, padding, encryptedBytes,
                    false, key, initializationVector);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            decrypt = new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return decrypt;
    }

    private String prefixAlgorithm(String prefix, String text) {
        StringBuilder sb = new StringBuilder("{");
        sb.append(prefix).append('}').append(text);
        return sb.toString();
    }

    private String getCipherTransformation(CryptoScheme scheme, String mode,
                                           String padding) {
        StringBuilder sb = new StringBuilder(scheme.getValue());
        if (mode != null && mode.length() != 0 && padding != null
                && padding.length() != 0) {
            sb.append("/" + mode + "/" + padding);
        }
        return sb.toString();
    }

    private Cipher getCipher(CryptoScheme scheme, String mode, String padding,
                             byte[] cipherValue, boolean isEncryptCipher, byte[] key,
                             byte[] initializationVector) throws Exception {
        if (scheme == null || CryptoScheme.isHashAlgorithm(scheme)
                || CryptoScheme.PLAINTEXT == scheme) {
            throw new IllegalArgumentException("Invalid encryption algorithm.");
        }
        String cipherStr = getCipherTransformation(scheme, mode, padding);
        Cipher cipher = Cipher.getInstance(cipherStr);

        // Constructing they key specifications for each of the algorithms
        KeySpec keySpec = getKeySpec(scheme, key);
        SecretKey secretKey = null;
        if (scheme != CryptoScheme.AES) {
            secretKey = SecretKeyFactory.getInstance(scheme.getValue())
                    .generateSecret(keySpec);
        }

        // Constructing the algorithm parameters for each of the algorithms
        AlgorithmParameterSpec paramSpec = null;
        int cipherMode;
        int blockSize = cipher.getBlockSize();
        if (isEncryptCipher) {
            if (initializationVector != null) {
                if (initializationVector.length != blockSize) {
                    throw new IllegalArgumentException(
                            "Invalid initialization vector");
                }
            } else {
                initializationVector = new byte[blockSize];
                secureRandom.nextBytes(initializationVector);
            }
            paramSpec = new IvParameterSpec(initializationVector);
            cipherMode = Cipher.ENCRYPT_MODE;
        } else {
            if (initializationVector != null) {
                if (initializationVector.length != blockSize) {
                    throw new IllegalArgumentException(
                            "Invalid initialization vector");
                }
                paramSpec = new IvParameterSpec(initializationVector);
            } else {
                if (cipherValue.length < blockSize) {
                    return null;
                }
                paramSpec = new IvParameterSpec(cipherValue, 0, blockSize);
            }
            cipherMode = Cipher.DECRYPT_MODE;
        }

        if (scheme == CryptoScheme.AES) {
            if (mode == null || mode.equals("ECB")) {
                cipher.init(cipherMode, (SecretKeySpec) keySpec);
            } else {
                cipher.init(cipherMode, (SecretKeySpec) keySpec, paramSpec);
            }
        } else {
            cipher.init(cipherMode, secretKey, paramSpec);
        }

        return cipher;
    }

    private KeySpec getKeySpec(CryptoScheme scheme, byte[] key)
            throws InvalidKeyException {
        KeySpec keySpec = null;
        byte[] keyBytes = null;
        if (key == null) {
            keyBytes = getEncryptionKey();
        } else {
            keyBytes = key;
        }
        if (scheme == CryptoScheme.AES) {
            keySpec = new SecretKeySpec(keyBytes, CryptoScheme.AES.getValue());
        } else
        // this is triple des
        {
            keySpec = new PBEKeySpec(String.valueOf(keyBytes).toCharArray());
        }

        return keySpec;
    }

    private byte[] getEncryptionKey() {
        if (encryptionKey != null) {
            return encryptionKey;
        }
        String encKeyStr = credStore.getString(ENCRYPTION_KEY);
        if (encKeyStr == null) {
            encryptionKey = new byte[ENCRYPTION_KEY_BYTE_LENGTH];
            secureRandom.nextBytes(encryptionKey);
            credStore.putString(ENCRYPTION_KEY, Base64.encode(encryptionKey));
        } else {
            encryptionKey = Base64.decode(encKeyStr);
        }
        return encryptionKey;
    }

    /**
     * This method compares the given plain text and the encoded text for
     * equality and returns true if they are same and false otherwise.
     *
     * @param plainText   plain text
     * @param encodedText encoded text
     * @param saltLength  salt length which is used if the given encoded text is hashed
     *                    with a salted algorithm
     * @return true / false
     * or you can use your custom key.
     * @deprecated Normally passwords are hashed. Hence, plainText given here can be password.
     * Storing password in String as opposed to char[] is a security concern. So, instead of this
     * method, use {@link #match(char[], char[], int, byte[])}.
     */
    @Deprecated
    public boolean match(String plainText, String encodedText, int saltLength) {
        return match(plainText, encodedText, saltLength, null);
    }

    /**
     * This method compares the given plain text and the encoded text for
     * equality and returns true if they are same and false otherwise. This
     * method accepts a custom key to perform this check .
     *
     * @param plainText   plain text
     * @param encodedText encoded text
     * @param saltLength  salt length which is used if the given encoded text is hashed
     *                    with a salted algorithm
     * @return true / false
     */
    public boolean match(char[] plainText, char[] encodedText, int saltLength,
                         byte[] key) {
        if (ArrayUtils.isEmpty(plainText) || ArrayUtils.isEmpty(encodedText)) {
            throw new IllegalArgumentException(
                    "Text for comparision cannot be null or empty.");
        }

        boolean isMatched = false;
        if (encodedText[0] != '{') {
            return isMatched;
        }

        int endIndex = ArrayUtils.indexOf(encodedText, '}');
        if (endIndex == -1 || endIndex == 1) {
            // endIndex == 1 means that encodedText starts with {} and algorithm is not specified.
            return isMatched;
        }

        int algorithmLength = endIndex - 1;
        char[] algorithm = new char[algorithmLength];
        System.arraycopy(encodedText, 1, algorithm, 0, algorithmLength);

        int encodedTextValueLength = encodedText.length - endIndex - 1;
        // New arrays created here (which contain sensitive info) MUST BE cleared in this method itself.
        char[] encodedTextValue = new char[encodedTextValueLength];
        if (OMSecurityConstants.DEBUG) {
            Log.v(TAG, "encodedText = " + Arrays.toString(encodedText));
        }
        System.arraycopy(encodedText, endIndex + 1, encodedTextValue, 0, encodedTextValueLength);

        byte[] encodedTextValueBytes = ArrayUtils.toBytes(encodedTextValue);
        byte[] plainTextBytes = ArrayUtils.toBytes(plainText);
        byte[] decryptedValueBytes = null;
        CryptoScheme scheme = CryptoScheme.getCryptoScheme(new String(algorithm));
        try {
            if (scheme != null && CryptoScheme.isHashAlgorithm(scheme)) {
                byte[] saltBytes = null;
                if (CryptoScheme.isSaltedHashAlgorithm(scheme)
                        && saltLength > 0) {
                    byte[] decodedBytes = Base64.bytesDecode(encodedTextValueBytes);
                    saltBytes = new byte[saltLength];
                    System.arraycopy(decodedBytes,
                            (decodedBytes.length - saltLength), saltBytes, 0,
                            saltLength);
                }
                String encodedValue = hash(plainTextBytes, scheme, saltLength,
                        saltBytes, false);
                if (encodedValue != null
                        && encodedValue.equals(new String(encodedTextValue))) {
                    isMatched = true;
                }
            } else if (CryptoScheme.PLAINTEXT == scheme) {
                if (Arrays.equals(plainTextBytes, encodedTextValueBytes)) {
                    isMatched = true;
                }
            } else {
                String decryptedValue;
                // if key is present then decrypt using this key else carry on
                // with the default key
                if (key != null) {
                    decryptedValue = decrypt(new String(encodedText), key);
                } else {
                    decryptedValue = decrypt(new String(encodedText));
                }
                if (decryptedValue != null) {
                    decryptedValueBytes = decryptedValue.getBytes(OMSecurityConstants.UTF_8);
                    if (Arrays.equals(decryptedValueBytes, plainTextBytes)) {
                        isMatched = true;
                    }
                }
            }
        } catch (Exception e) {
            Logger.getLogger(OMCryptoService.class.getName()).log(Level.INFO,
                    e.getLocalizedMessage(), e);
        } finally {
            Arrays.fill(encodedTextValue, ' ');
            if (encodedTextValueBytes != null) {
                Arrays.fill(encodedTextValueBytes, (byte) 0);
            }
            Arrays.fill(plainTextBytes, (byte) 0);
            if (decryptedValueBytes != null) {
                Arrays.fill(decryptedValueBytes, (byte) 0);
            }
        }
        return isMatched;
    }

    /**
     * This method compares the given plain text and the encoded text for
     * equality and returns true if they are same and false otherwise. This
     * method accepts a custom key to perform this check .
     *
     * @param plainText   plain text
     * @param encodedText encoded text
     * @param saltLength  salt length which is used if the given encoded text is hashed
     *                    with a salted algorithm
     * @return true / false
     * @deprecated Normally passwords are hashed. Hence, plainText given here can be password.
     * Storing password in String as opposed to char[] is a security concern. So, instead of this
     * method, use {@link #match(char[], char[], int, byte[])}.
     */
    @Deprecated
    public boolean match(String plainText, String encodedText, int saltLength,
                         byte[] key) {
        if (plainText == null || plainText.length() == 0 || encodedText == null
                || encodedText.length() == 0) {
            throw new IllegalArgumentException(
                    "Text for comparision cannot be null or empty.");
        }
        return match(plainText.toCharArray(), encodedText.toCharArray(), saltLength, key);
    }

    /**
     * Gets a decrypted plain text for the given encrypted input text.
     *
     * @param encryptedText text to be decrypted
     * @return plain text
     * @throws CryptoException          if any exception occurred in the process of encryption
     * @throws IllegalArgumentException If the input text is empty or null, If the input text doesn't
     *                                  have the algorithm prefixed.
     */
    @Deprecated
    public String decrypt(String encryptedText) throws CryptoException {
        if (encryptedText == null || encryptedText.length() == 0) {
            throw new IllegalArgumentException(
                    "Encrypted text cannot be null or empty.");
        }

        if (!encryptedText.startsWith("{")) {
            throw new IllegalArgumentException(
                    "Encrypted text doesn't specify the algorithm for decryption.");
        }
        int endIndex = encryptedText.indexOf("}");
        String algorithm = encryptedText.substring(1, endIndex);
        String encodedTextValue = encryptedText.substring(endIndex + 1);

        StringTokenizer st = new StringTokenizer(algorithm, "/");
        int i = 0;
        CryptoScheme scheme = null;
        String mode = null;
        String padding = null;
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            // this is the algorithm name
            if (i == 0)
                scheme = CryptoScheme.getCryptoScheme(token);
                // this is the mode
            else if (i == 1)
                mode = token;
                // this is the padding
            else
                padding = token;
            i++;
        }

        return decrypt(encodedTextValue, scheme, mode, padding);
    }

    /**
     * Gets a de-crypted plain text for the given encrypted input text.
     *
     * @param encryptedText text to be de-crypted
     * @param scheme        encryption algorithm
     * @param mode          mode for the encryption algorithm
     * @param padding       padding for the encryption algorithm
     * @return plain text
     * @throws CryptoException          if any exception occurred in the process of encryption
     * @throws IllegalArgumentException If the input text is empty or null
     */
    @Deprecated
    public String decrypt(String encryptedText, CryptoScheme scheme,
                          String mode, String padding) throws CryptoException {
        if (encryptedText == null || encryptedText.length() == 0) {
            throw new IllegalArgumentException(
                    "Encrypted text cannot be null or empty.");
        }

        String decrypt = null;
        try {
            byte[] encryptedBytes = Base64.decode(encryptedText);
            Cipher cipher = getCipher(scheme, mode, padding, encryptedBytes,
                    false, null, null);
            int blockSize = cipher.getBlockSize();
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes, blockSize,
                    (encryptedBytes.length - blockSize));

            decrypt = new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return decrypt;
    }

    /**
     * Gets a decrypted plain text for the given encrypted input text with the
     * key used during encryption.
     *
     * @param encryptedText
     * @param key           key to decrypt the encrypted text
     * @return
     * @throws CryptoException
     */
    public String decrypt(String encryptedText, byte[] key)
            throws CryptoException {
        if (encryptedText == null || encryptedText.length() == 0) {
            throw new IllegalArgumentException(
                    "Encrypted text cannot be null or empty.");
        }

        if (!encryptedText.startsWith("{")) {
            throw new IllegalArgumentException(
                    "Encrypted text doesn't specify the algorithm for decryption.");
        }
        int endIndex = encryptedText.indexOf("}");
        String algorithm = encryptedText.substring(1, endIndex);
        String encodedTextValue = encryptedText.substring(endIndex + 1);

        StringTokenizer st = new StringTokenizer(algorithm, "/");
        int i = 0;
        CryptoScheme scheme = null;
        String mode = null;
        String padding = null;
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            // this is the algorithm name
            if (i == 0)
                scheme = CryptoScheme.getCryptoScheme(token);
                // this is the mode
            else if (i == 1)
                mode = token;
                // this is the padding
            else
                padding = token;
            i++;
        }

        return decrypt(encodedTextValue, scheme, mode, padding, key);
    }
}
