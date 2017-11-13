/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.os.Handler;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import oracle.idm.mobile.auth.OMAuthenticationContext.TimeoutType;
import oracle.idm.mobile.callback.OMAuthenticationContextCallback;
import oracle.idm.mobile.logging.OMLog;

/**
 * Utility class to handle timeouts. It provides methods to start, reset and stop timers.
 * @hide
 */
public class TimeoutManager {
    private static final String TAG = TimeoutManager.class.getSimpleName();
    private static final int CORE_POOL_SIZE = 15;
    ScheduledThreadPoolExecutor scheduler;
    int mIdleTimeout, mSessionTimeout, mAdvanceNotification;
    OMAuthenticationContextCallback mCallback;
    ScheduledFuture mIdleTimeoutTimer, mAdvanceNotificationTimer, mSessionTimeoutTimer;
    OMAuthenticationContext mAuthContext;
    Handler mHandler;

    TimeoutManager(OMAuthenticationContextCallback callback, OMAuthenticationContext authContext, Handler handler) {
        mIdleTimeout = authContext.getIdleTimeExpInSecs();
        mSessionTimeout = authContext.getSessionExpInSecs();
        mAdvanceNotification = authContext.getAuthenticationServiceManager().getMSS().getMobileSecurityConfig().getAdvanceTimeoutNotification();
        mCallback = callback;
        mAuthContext = authContext;
        mHandler = handler;
        scheduler = (ScheduledThreadPoolExecutor)
                Executors.newScheduledThreadPool(CORE_POOL_SIZE);
    }

    /**
     * Method to start Advance idleTimeout notification and sessionTimeout timer.
     */
    void startTimers() {
        OMLog.trace(TAG, "Start the timers");
        startIdleTimeoutTimer();
        startSessionTimeoutTimer();
    }

    void startSessionTimeoutTimer() {
        OMLog.trace(TAG, "Start the startSessionTimeoutTimer");
        mSessionTimeoutTimer = scheduler.schedule(sessionTimeoutTask, mSessionTimeout, TimeUnit.SECONDS);
    }

    void startIdleTimeoutTimer() {
        OMLog.trace(TAG, "Start the startIdleTimeoutTimer");
        long timeout = (long) Math.round(mIdleTimeout * (1.0d - ((double) mAdvanceNotification / 100)));

        mAdvanceNotificationTimer = scheduler.schedule(advanceNotificationTask, timeout, TimeUnit.SECONDS);
    }

    /**
     * Task to be executed on Advance Idletimeout notification ( at T{i}-T{inot}):
     * 1. Invoking application callback
     * 2. Scheduling task for IdleTimeout( with delay T{inot} )
     * where T{inot} is the advance time before the actual idle time out occurs.
     */
    Runnable advanceNotificationTask = new Runnable() {
        public void run() {
            OMLog.debug(TAG, "Idle Time expires in seconds " + mIdleTimeout * mAdvanceNotification / 100);
            onTimeout(TimeoutType.IDLE_TIMEOUT, mIdleTimeout * mAdvanceNotification / 100);
            long timeout = (long) Math.round(mIdleTimeout * (double) mAdvanceNotification / 100);
            mIdleTimeoutTimer = scheduler.schedule(idleTimeoutTask, timeout, TimeUnit.SECONDS);
        }
    };

    /**
     * Task to be executed on SessionTimeout :
     * 1. Invoking app callback
     * 2. Invalidating AuthContext
     */
    Runnable sessionTimeoutTask = new Runnable() {
        public void run() {
            OMLog.debug(TAG, "Session Time expired");
            onTimeout(TimeoutType.SESSION_TIMEOUT, 0);
            stopTimers();
            mAuthContext.isValid(false);

        }
    };

    /**
     * Task to be executed on actual IdleTimeout :
     * 1. Invoking app callback
     * 2. Invalidating AuthContext
     */
    Runnable idleTimeoutTask = new Runnable() {
        public void run() {
            OMLog.debug(TAG, "Idle Time expired");
            onTimeout(TimeoutType.IDLE_TIMEOUT, 0);
            // mAuthContext.getAuthenticationServiceManager().loadAllAuthenticationServices();
            if (mAuthContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.FEDERATED) {
                /*In case of fed auth, idle timeout and session timeout lead to same behavior, that is loading of logout url.
                * Hence, we stop session timer in case of fed auth upon idle timeout. The reverse scenario (cancellation of
                * idle timeout on session timeout) does not arise, as idle < session timeout.*/
                stopSessionTimer();
            }
            mAuthContext.isValid(false);
            ((BasicAuthenticationService) (mAuthContext.getAuthenticationServiceManager().getAuthService(AuthenticationService.Type.BASIC_SERVICE))).setIdleTimeOut(true);
        }
    };

    /**
     * Method to reset IdleTimeout. It checks if Idletimeout has already occured and returns false, if not cancels
     * scheduled tasks for idleTimeout (if any) and schedules new task for advance IdleTimeout Notification.
     *
     * @return true, if timer is successfully reset
     */
    boolean resetTimer() {
        if (scheduler.isShutdown() ||
                mAdvanceNotificationTimer == null || mIdleTimeoutTimer == null ||
                ((mAdvanceNotificationTimer != null && mAdvanceNotificationTimer.isDone()) &&
                        (mIdleTimeoutTimer != null && mIdleTimeoutTimer.isDone()))) {
            OMLog.error(TAG, "Could not reset the timers");
            return false;
        }

        boolean resetTimerStatus = mAdvanceNotificationTimer.cancel(true);
        if (mIdleTimeoutTimer != null) {
            resetTimerStatus = resetTimerStatus || mIdleTimeoutTimer.cancel(true);
        }
        long timeout = (long) Math.round(mIdleTimeout * (1.0d - ((double) mAdvanceNotification / 100)));
        mAdvanceNotificationTimer = scheduler.schedule(advanceNotificationTask, timeout, TimeUnit.SECONDS);
        OMLog.debug(TAG, " resetTimerStatus " + resetTimerStatus);
        return resetTimerStatus;
    }

    /**
     * @hide
     */
    public void stopTimers() {
        OMLog.debug(TAG, "Invalidating the timers");
        if (mIdleTimeoutTimer != null && !mIdleTimeoutTimer.isDone())
            mIdleTimeoutTimer.cancel(true);
        if (mAdvanceNotificationTimer != null && !mAdvanceNotificationTimer.isDone())
            mAdvanceNotificationTimer.cancel(true);
        if (mSessionTimeoutTimer != null && !mSessionTimeoutTimer.isDone())
            mSessionTimeoutTimer.cancel(true);

        mIdleTimeoutTimer = null;
        mAdvanceNotificationTimer = null;
        mSessionTimeoutTimer = null;

        scheduler.shutdown();
    }

    private void stopSessionTimer() {
        OMLog.debug(TAG, "Stopping session timer");

        if (mSessionTimeoutTimer != null && !mSessionTimeoutTimer.isDone()) {
            boolean stopSessionTimerStatus = mSessionTimeoutTimer.cancel(true);
            OMLog.debug(TAG, "stopSessionTimerStatus " + stopSessionTimerStatus);
        } else {
            OMLog.debug(TAG, "Session timer is NOT scheduled");
        }

        mSessionTimeoutTimer = null;

        scheduler.shutdown();
    }

    /**
     * Utility method for invoking app callback on UI thread.
     *
     * @param type     Timeout type
     * @param timeLeft Time left for timeout in seconds
     */
    void onTimeout(final TimeoutType type, final long timeLeft) {
        if (mHandler != null) {
            mHandler.post(new Runnable() {
                public void run() {
                    if (mCallback != null) {
                        mCallback.onTimeout(type, timeLeft);
                    }
                }
            });
        }
    }

}


