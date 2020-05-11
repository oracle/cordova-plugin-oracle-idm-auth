/*
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Arrays;
import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.credentialstore.OMCredential;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.ArrayUtils;

/**
 * This is used as the AuthServiceInputCallback implementation for basic and offline authentication mechanisms.
 */

class UsernamePasswdAuthServiceInputCallbackImpl implements AuthServiceInputCallback {

    private static final String TAG = UsernamePasswdAuthServiceInputCallbackImpl.class.getSimpleName();
    private AuthenticationServiceManager mASM;
    private ASMInputController mASMInputController;

    UsernamePasswdAuthServiceInputCallbackImpl(AuthenticationServiceManager asm, ASMInputController asmInputController) {
        mASM = asm;
        mASMInputController = asmInputController;
    }

    @Override
    public void onInput(final Map<String, Object> inputs) {
        if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
            //lets update the RC UI preferences.

            OMLog.info(TAG, "Remember Cred feature is enabled, Storing UI prefs");
            //check for the password.
            //we already have the password.
            //usually in case of remember creds and auto login we check for this.
            OMMobileSecurityConfiguration config = mASM.getMSS().getMobileSecurityConfig();
            if (config.isAutoLoginEnabled() || config.isRememberCredentialsEnabled()) {
                RCUtility rcUtility = mASM.getRCUtility();
                OMCredential remCred = rcUtility.retrieveRememberedCredentials();
                if (remCred != null && !(ArrayUtils.isEmpty(remCred.getUserPasswordAsCharArray()))
                        && isInputPasswordSameAsObfuscatedPassword(inputs)) {
                    //this means the creds are already persisted and the user did not change the password which was pre-filled in the login screen.
                    //TODO if possible we should change this impl.
                    OMLog.info(TAG, "Updating the obfuscated PWD with the one we have in the store.");
                    inputs.put(OMSecurityConstants.Challenge.PASSWORD_KEY_2, remCred.getUserPasswordAsCharArray());
                }
            }
            storeRCUIPreferences(inputs);
        }
        mASMInputController.onInputAvailable(inputs);
    }

    @Override
    public void onError(final OMErrorCode error) {
        mASMInputController.onInputError(error);
    }

    @Override
    public void onCancel() {
        //FIXME Clear cookies which were set during this basic authentication attempt
        mASMInputController.onCancel();
    }

    private boolean isInputPasswordSameAsObfuscatedPassword(Map<String, Object> inputs) {
        char[] inputPWDCharArray = (char[]) inputs.get(OMSecurityConstants.Challenge.PASSWORD_KEY_2);
        String inputPWDString = (String) inputs.get(OMSecurityConstants.Challenge.PASSWORD_KEY);
        if (!ArrayUtils.isEmpty(inputPWDCharArray)) {
            return Arrays.equals(inputPWDCharArray, RCUtility.OBFUSCATED_PWD_CHAR_ARRAY);
        } else {
            return inputPWDString.equalsIgnoreCase(RCUtility.OBFUSCATED_PWD);
        }
    }

    private void storeRCUIPreferences(Map<String, Object> prefs) {
        mASM.getRCUtility().storeRememberCredentialsUIPreferences(prefs);
    }
}
