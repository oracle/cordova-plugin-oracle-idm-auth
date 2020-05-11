/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.logging;

public class OMLogManager {

    public enum LogLevel {
        TRACE, DEBUG, INFO, WARN, ERROR
    }

    private static volatile OMLogManager mInstance;
    private static final LogLevel DEFAULT_LEVEL = LogLevel.TRACE;
    private LogLevel mLevel;
    private boolean mLoggingEnabled = true;

    private OMLogManager() {
        this.setLevel(DEFAULT_LEVEL);
    }

    public static OMLogManager getInstance() {
        if (mInstance == null) {
            synchronized (OMLogManager.class) {
                if (mInstance == null) {
                    mInstance = new OMLogManager();
                }
            }
        }
        return mInstance;
    }

    public void setLevel(LogLevel level) {
        mLevel = level;
    }

    public LogLevel getLevel() {
        return mLevel;
    }

    /**
     * By default, logging is enabled. It can be disabled using
     * {@link #setLoggingEnabled(boolean)}.
     *
     */
    public boolean isLoggingEnabled() {
        return mLoggingEnabled;
    }

    public void setLoggingEnabled(boolean loggingEnabled) {
        this.mLoggingEnabled = loggingEnabled;
    }

    static boolean isInitialised() {
        return (null != mInstance);
    }


}
