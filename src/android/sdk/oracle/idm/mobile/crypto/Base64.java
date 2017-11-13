/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

package oracle.idm.mobile.crypto;

import java.io.UnsupportedEncodingException;

/**
 * Provides encoding of raw bytes to base64 encoded bytes and decoding of base64
 * encoded bytes to raw bytes.
 *
 * @version 1.0
 */
public class Base64 {
    /**
     * the Base 64 Characterset
     */
    private final static byte[] charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .getBytes();

    /**
     * lookup table for mapping the base64 characters [0..63]
     */
    private static byte[] binaryCodes = new byte[256];

    static {
        for (int i = 0; i < 256; i++)
            binaryCodes[i] = -1;
        binaryCodes['+'] = 62;
        binaryCodes['/'] = 63;
        for (int i = '0'; i <= '9'; i++)
            binaryCodes[i] = (byte) (52 + i - '0');
        for (int i = 'a'; i <= 'z'; i++)
            binaryCodes[i] = (byte) (26 + i - 'a');
        for (int i = 'A'; i <= 'Z'; i++)
            binaryCodes[i] = (byte) (i - 'A');
    }

    /**
     * Use this method to convert a string to Base64-encoded string.
     *
     * @param inStr String to be Base64 encoded.
     * @return outStr Base64 encoded string.
     */
    public static String stringEncode(String inStr) {
        String outStr = null;
        if (inStr != null)
            outStr = new String(bytesEncode(inStr.getBytes()));

        return outStr;
    }

    public static String encode(byte[] inBytes) {
        String outStr = null;
        try {
            if (inBytes != null)
                outStr = new String(bytesEncode(inBytes), "UTF-8");
        } catch (UnsupportedEncodingException uex) {
            outStr = new String(bytesEncode(inBytes));
        }

        return outStr;
    }

    /**
     * Use this method to convert a UTF-8string to Base64-encoded string.
     *
     * @param inStr String to be Base64 encoded.
     * @return outStr Base64 encoded string.
     */
    public static String utfEncode(String inStr) {
        String outStr = null;
        try {
            if (inStr != null)
                outStr = new String(bytesEncode(inStr.getBytes("UTF-8")),
                        "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            throw new IllegalArgumentException(uee.getMessage());
        }

        return outStr;
    }

    /**
     * Use this method to decode a Base64 encoded string to the orginal String.
     *
     * @param inStr Base64 encoded string.
     * @return outStr The orginal string.
     */
    public static String stringDecode(String inStr) {
        String outStr = null;
        if (inStr != null)
            outStr = new String(bytesDecode(inStr.getBytes()));
        return outStr;
    }

    public static byte[] decode(String inStr) {
        byte[] outBytes = null;
        try {
            if (inStr != null)
                outBytes = bytesDecode(inStr.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException uex) {
            outBytes = bytesDecode(inStr.getBytes());
        }
        return outBytes;
    }

    /**
     * Use this method to decode a UTF8Base64 encoded string to the orginal
     * String.
     *
     * @param inStr Base64 encoded string.
     * @return outStr The orginal string.
     */
    public static String utfDecode(String inStr) {
        String outStr = null;
        try {
            if (inStr != null)
                outStr = new String(bytesDecode(inStr.getBytes("UTF-8")),
                        "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            throw new IllegalArgumentException(uee.getMessage());
        }

        return outStr;
    }

    /**
     * returns an array of base64-encoded characters to represent the passed
     * data array.
     *
     * @param inBytes the array of bytes to encode
     * @return base64-coded byte array.
     */
    public static byte[] bytesEncode(byte[] inBytes) {
        byte[] outBytes = new byte[((inBytes.length + 2) / 3) * 4];

        /*
         * convert every 3 bytes to 4 bytes
         */
        for (int ix = 0, index = 0; ix < inBytes.length; ix += 3, index += 4) {
            boolean byte2Present = false;
            boolean byte3Present = false;

            int val = unsignedByteToInt(inBytes[ix]) << 8;
            if ((ix + 1) < inBytes.length) {
                val |= unsignedByteToInt(inBytes[ix + 1]);
                byte2Present = true;
            }
            val <<= 8;
            if ((ix + 2) < inBytes.length) {
                val |= unsignedByteToInt(inBytes[ix + 2]);
                byte3Present = true;
            }
            outBytes[index + 3] = (byte) (byte3Present ? charset[val & 0x3F]
                    : '=');
            val >>= 6;
            outBytes[index + 2] = (byte) (byte2Present ? charset[val & 0x3F]
                    : '=');
            val >>= 6;
            outBytes[index + 1] = charset[val & 0x3F];
            val >>= 6;
            outBytes[index + 0] = charset[val & 0x3F];
        }
        return outBytes;
    }

    /**
     * Decode a BASE-64 encoded sequence bytes. All illegal symbols in the input
     * are ignored (CRLF, Space).
     *
     * @param inBytes A sequence of Base 64 encoded bytes.
     * @return The original data from the BASE-64 input.
     */
    public static byte[] bytesDecode(byte[] inBytes) {
        int len = inBytes.length;
        byte[] outBytes;
        byte[] tmpBytes;

        for (int ix = 0; ix < inBytes.length; ix++)
            if (binaryCodes[inBytes[ix]] < 0)
                len--;

        int tmpBytesLen = ((len + 3) / 4) * 3;

        tmpBytes = new byte[tmpBytesLen];

        int tempBuf = 0;
        int prevBits = 0;
        int jx = 0;
        for (int ix = 0; ix < inBytes.length; ix++) {
            int val = binaryCodes[inBytes[ix]];
            if (val >= 0) {
                tempBuf = (tempBuf << 6) | val;
                if (prevBits >= 2) {
                    prevBits -= 2;
                    tmpBytes[jx++] = (byte) ((tempBuf >> prevBits) & 0xff);
                } else
                    prevBits += 6;
            }
        }
        outBytes = new byte[jx];
        System.arraycopy(tmpBytes, 0, outBytes, 0, jx);

        return outBytes;
    }

    /**
     * A helper method converts the unsigned byte to integer for e.x byte -64
     * ---> int 192 byte -1 ---> int 255 byte -128 ---> int 256
     */
    private static int unsignedByteToInt(byte b) {
        return (int) b & 0xFF;
    }
}
