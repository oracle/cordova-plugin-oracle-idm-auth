/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

/**
 * Authentication policy.
 */
public class OMAuthenticationPolicy {

    /**
     * maximum number of failure before giving warning to user
     */
    private int maxFailuresBeforeWarning;

    /**
     * maximum number of failure before locking application
     */
    private int maxFailuresBeforeLockout;

    /**
     * initial lockout period in seconds
     */
    private int initialLockoutPeriod;

    /* lockout escalation pattern */
    private String lockoutEscalationPattern;

    /**
     * maximum lockout interval
     */
    private int maxLockoutInterval;

    /**
     * minimum pin length
     */
    private int minPinLength;

    private boolean okToLoseKeys;

    public int getMaxFailuresBeforeWarning() {
        return maxFailuresBeforeWarning;
    }

    public void setMaxFailuresBeforeWarning(int maxFailuresBeforeWarning) {
        this.maxFailuresBeforeWarning = maxFailuresBeforeWarning;
    }

    public int getMaxFailuresBeforeLockout() {
        return maxFailuresBeforeLockout;
    }

    public void setMaxFailuresBeforeLockout(int maxFailuresBeforeLockout) {
        this.maxFailuresBeforeLockout = maxFailuresBeforeLockout;
    }

    public int getInitialLockoutPeriod() {
        return initialLockoutPeriod;
    }

    public void setInitialLockoutPeriod(int initialLockoutPeriod) {
        this.initialLockoutPeriod = initialLockoutPeriod;
    }

    public String getLockoutEscalationPattern() {
        return lockoutEscalationPattern;
    }

    public void setLockoutEscalationPattern(String lockoutEscalationPattern) {
        this.lockoutEscalationPattern = lockoutEscalationPattern;
    }

    public int getMaxLockoutInterval() {
        return maxLockoutInterval;
    }

    public void setMaxLockoutInterval(int maxLockoutInterval) {
        this.maxLockoutInterval = maxLockoutInterval;
    }

    public int getMinPinLength() {
        return minPinLength;
    }

    public void setMinPinLength(int minPinLength) {
        this.minPinLength = minPinLength;
    }

    public boolean isOkToLoseKeys() {
        return okToLoseKeys;
    }

    /**
     * In case of {@link OMDefaultAuthenticator}, keys in {@link OMDefaultAuthenticator#getKeyStore()}
     * will be deleted if secure lock screen is disabled or reset (for example, by the user or a Device
     * Administrator). This is because AndroidKeyStore is used internally and this problem is present
     * only from Android 4.3 (inclusive) to 6.0 (exclusive). But, this will
     * ensure that keys cannot be extracted from device in these versions. If keys should not be lost,
     * then use this setter with false value. In this case, {@link OMDefaultAuthenticator} will use
     * a key derived from device parameters to secure the keys in {@link OMDefaultAuthenticator#getKeyStore()}.
     * Please note that this will result in weakened security.
     *
     * @param okToLoseKeys
     */
    public void setOkToLoseKeys(boolean okToLoseKeys) {
        this.okToLoseKeys = okToLoseKeys;
    }
}
