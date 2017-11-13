/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.logging;

import oracle.idm.mobile.OMSecurityConstants;

public class OMLog {
    private static OMLogger mLogger = new OMLogger(OMSecurityConstants.TAG);

    public static void trace(String tag, String msg)
    {
        mLogger.trace(tag, msg);
    }

    public static void debug(String tag, String msg)
    {
        mLogger.debug(tag, msg);
    }

    public static void info(String tag, String msg)
    {
        mLogger.info(tag, msg);
    }

    public static void warn(String tag, String msg)
    {
        mLogger.warn(tag, msg);
    }

    public static void error(String tag, String msg)
    {
        mLogger.error(tag, msg);
    }

    //TODO add similar methods with tr
    public static void trace(String tag, String msg, Throwable tr)
    {
        mLogger.trace(tag, msg, tr);
    }

    public static void debug(String tag, String msg, Throwable tr)
    {
        mLogger.debug(tag, msg, tr);
    }

    public static void info(String tag, String msg, Throwable tr)
    {
        mLogger.info(tag, msg, tr);
    }

    public static void warn(String tag, String msg, Throwable tr)
    {
        mLogger.warn(tag, msg, tr);
    }

    public static void error(String tag, String msg, Throwable tr)
    {
        mLogger.error(tag, msg, tr);
    }
}
