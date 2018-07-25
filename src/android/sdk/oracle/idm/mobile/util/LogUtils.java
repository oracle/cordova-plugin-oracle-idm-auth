/*
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

import android.text.TextUtils;

import oracle.idm.mobile.logging.OMLog;

/**
 * Log utility class
 */
public class LogUtils {
    private static final String TAG = LogUtils.class.getName();

    /**
     * This method splits the input string to be logged into chunks so that the
     * entire string is logged properly.
     * <p>
     * Note: This is being used only for debug build.
     */
    public static void log(String msg) {
        if (!TextUtils.isEmpty(msg) && msg.length() > 4000) {
            OMLog.trace(TAG, "Length of String = " + msg.length());
            int chunkCount = msg.length() / 4000;
            for (int i = 0; i <= chunkCount; i++) {
                int max = 4000 * (i + 1);
                if (max >= msg.length()) {
                    OMLog.trace(TAG,
                            "chunk " + i + " of " + chunkCount + ":"
                                    + msg.substring(4000 * i));
                } else {
                    OMLog.trace(TAG,
                            "chunk " + i + " of " + chunkCount + ":"
                                    + msg.substring(4000 * i, max));
                }
            }
        } else {
            OMLog.trace(TAG, "Message: " + msg);
        }
    }
}
