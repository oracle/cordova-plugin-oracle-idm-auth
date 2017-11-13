/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.logging;

import android.text.TextUtils;
import android.util.Log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.NOPLogger;

import oracle.idm.mobile.OMSecurityConstants;

public class OMLogger
{
    private Logger mLogger = null;
    private String mTagName;

    public OMLogger(String name)
    {
        mLogger = LoggerFactory.getLogger(name);
        mTagName = name;
    }

    public OMLogger(Class className)
    {
        mLogger = LoggerFactory.getLogger(className);
        mTagName = className.getSimpleName();
    }

    public void trace(String msg)
    {
        log(OMLogManager.LogLevel.TRACE, msg);
    }

    public void debug(String msg)
    {
        log(OMLogManager.LogLevel.DEBUG, msg);
    }

    public void info(String msg)
    {
        log(OMLogManager.LogLevel.INFO, msg);
    }

    public void warn(String msg)
    {
        log(OMLogManager.LogLevel.WARN, msg);
    }

    public void error(String msg)
    {
        log(OMLogManager.LogLevel.ERROR, msg);
    }

    public void trace(String tag, String msg)
    {
        log(OMLogManager.LogLevel.TRACE, tag,  msg);
    }

    public void debug(String tag, String msg)
    {
        log(OMLogManager.LogLevel.DEBUG, tag,  msg);
    }

    public void info(String tag, String msg)
    {
        log(OMLogManager.LogLevel.INFO, tag,  msg);
    }

    public void warn(String tag, String msg)
    {
        log(OMLogManager.LogLevel.WARN, tag, msg);
    }

    public void error(String tag, String msg)
    {
        log(OMLogManager.LogLevel.ERROR, tag, msg);
    }

    public void trace(String tag, String msg, Throwable tr) {
        log(OMLogManager.LogLevel.TRACE, tag, msg, tr);
    }

    public void debug(String tag, String msg, Throwable tr) {
        log(OMLogManager.LogLevel.DEBUG, tag, msg, tr);
    }

    public void info(String tag, String msg, Throwable tr) {
        log(OMLogManager.LogLevel.INFO, tag, msg, tr);
    }

    public void warn(String tag, String msg, Throwable tr) {
        log(OMLogManager.LogLevel.WARN, tag, msg, tr);
    }

    public void error(String tag, String msg, Throwable tr)
    {
        log(OMLogManager.LogLevel.ERROR, tag, msg, tr);
    }

    private void log(OMLogManager.LogLevel level, String msg) {
        log(level, OMSecurityConstants.EMPTY_STRING, msg);
    }

    private void log(OMLogManager.LogLevel level, String tag, String msg) {
        log(level, tag, msg, null);
    }

    private void log(OMLogManager.LogLevel level, String tag, String msg, Throwable tr) {
        String logMsg;

        if(OMLogManager.isInitialised() && OMLogManager.getInstance().getLevel().ordinal() > level.ordinal())
        {
            return;
        }

        if(TextUtils.isEmpty(tag)) {
            logMsg = msg;
        }
        else {
            logMsg = new StringBuilder()
                    .append(OMSecurityConstants.OPEN_BRACKET)
                    .append(tag)
                    .append(OMSecurityConstants.CLOSE_BRACKET)
                    .append(msg).toString();
        }

        // use android logging when no logging framework is bound with SLF4J
        if(mLogger instanceof NOPLogger)
        {
            switch (level) {
                case TRACE :
                    Log.v(mTagName, logMsg, tr);
                    break;
                case DEBUG:
                    Log.d(mTagName, logMsg, tr);
                    break;
                case INFO:
                    Log.i(mTagName, logMsg, tr);
                    break;
                case WARN:
                    Log.w(mTagName, logMsg, tr);
                    break;
                case ERROR:
                    Log.e(mTagName, logMsg, tr);
            }
        }
        else
        {
            // http://jira.qos.ch/browse/SLF4J-314
            switch (level) {
                case TRACE :
                case DEBUG:
                case INFO:
                    mLogger.info(logMsg, tr);
                    break;
                case WARN:
                    mLogger.warn(logMsg, tr);
                    break;
                case ERROR:
                    mLogger.error(logMsg, tr);
            }

        }
    }

}
