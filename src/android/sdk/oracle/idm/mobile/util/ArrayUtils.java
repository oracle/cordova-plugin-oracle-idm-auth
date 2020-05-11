/*
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

import oracle.idm.mobile.OMSecurityConstants;

/**
 * Utility methods related to arrays.
 */

public class ArrayUtils {

    /**
     * Converts given char[] to byte[] using UTF-8 encoding.
     */
    public static byte[] toBytes(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = Charset.forName(OMSecurityConstants.UTF_8).encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        /* charBuffer.array() is not cleared as it's backing array is the input.
        * The caller manages the input and they should clear it, if needed.
        * byteBuffer.array() is an array which got created in this method. Hence, clearing it.*/
        Arrays.fill(byteBuffer.array(), (byte) 0);
        return bytes;
    }

    /**
     * Returns the first index where given character is present in the array,
     * -1 if it is not present.
     */
    public static int indexOf(char[] chars, char element) {
        int index = -1;
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == element) {
                index = i;
                break;
            }
        }
        return index;
    }

    /**
     * Returns true if given array is null or its length is zero.
     */
    public static boolean isEmpty(char[] input) {
        return (input == null || input.length == 0);
    }

}
