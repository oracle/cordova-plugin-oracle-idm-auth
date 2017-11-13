/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.credentialstore.OMCredential;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.logging.OMLog;


/**
 * Utility class for Remember Credential feature.
 */
class RCUtility {
    private static final String TAG = RCUtility.class.getSimpleName();

    final static int OPTION_SELECTED_BY_USER = 1;
    final static int OPTION_UNSELECTED_BY_USER = -1;
    final static String OBFUSCATED_PWD = "********";
    // Strings to be suffixed to the app credential key to store the
    // Remember credential related info in the store //
    static String KEY_SUFFIX_REMEMBER_CREDENTIALS = "_RC";
    static String KEY_SUFFIX_AUTO_LOGIN_UI_PREF_BY_USER = "_autoLoginFromUser";
    static String KEY_SUFFIX_REMEMBER_CREDENTIALS_UI_PREF_BY_USER = "_rememberCredentialsFromUser";
    static String KEY_SUFFIX_REMEMBER_USERNAME_UI_PREF_BY_USER = "_rememberUsernameFromUser";
    static String AUTO_LOGIN_UI_PREF_STORAGE_KEY = "";
    static String REMEMBER_USERNAME_UI_PREF_STORAGE_KEY = "";
    static String REMEMBER_CREDENTIALS_UI_PREF_STORAGE_KEY = "";
    private String mKey;
    private Context mContext;

    OMMobileSecurityConfiguration mConfig;
    OMCredentialStore mCredentialStore;

    RCUtility(Context context, OMMobileSecurityConfiguration config, OMCredentialStore credentialStore) {
        mContext = context;
        mConfig = config;
        mCredentialStore = credentialStore;
        mKey = config.getAuthenticationURL().toString();
        //TODO get the credential Key from configuration
        //keeping it login URL for now to maintain RC per authentication server.
    }

    void storeRememberCredentialsUIPreferences(Map<String, Object> params) {
        //should be called when the app calls proceed on the completion handler.
        // this will ensure that user preferences from UI are stored
        // moment the user presses login
        OMLog.info(TAG, "Trying to store remember credentials UI preferences");
        if (mConfig.isAutoLoginEnabled()) {
            OMLog.info(TAG, "Auto Login Enabled in Init Config, So lets persist its UI preferences");
            Object autoLoginUIObj = params
                    .get(OMSecurityConstants.Challenge.AUTO_LOGIN_UI_PREFERENCE_KEY);
            if (autoLoginUIObj != null) {
                setAutoLoginUIPrefToStore((Boolean) autoLoginUIObj);
            } else {
                boolean defaultValue = mConfig.getDefaultValueForAutoLogin();
                OMLog.debug(TAG,
                        "No UI flag for Auto Login found [OM_AUTO_LOGIN_UI_PREF] so setting it as default value from init i.e. = "
                                + defaultValue);
                setAutoLoginUIPrefToStore(defaultValue);
            }
        } else {
            OMLog.info(TAG, "Auto Login Not Enabled in the Init Config, Skip persisting of UI preferences");
        }

        if (mConfig.isRememberCredentialsEnabled()) {
            OMLog.info(TAG, "Remember Credentials Enabled in Init Config, So lets persist its UI preferences");
            Object remCredUIObj = params
                    .get(OMSecurityConstants.Challenge.REMEMBER_CREDENTIALS_UI_PREFERENCE_KEY);
            if (remCredUIObj != null) {
                setRememberCredentialsUIPrefToStore((Boolean) remCredUIObj);
            } else {
                boolean defaultValue = mConfig.getDefaultValueForRememberCredentials();
                OMLog.debug(TAG,
                        "No UI flag for Remember Credentials found [OM_REMEMBER_CREDENTIALS_PREF] so setting it as default value from init = "
                                + defaultValue);
                setRememberCredentialsUIPrefToStore(defaultValue);
            }
        } else {
            OMLog.info(TAG, "Remember Credentials Not Enabled in the Init Config, Skip persisting of UI preferences");
        }
        if (mConfig.isRememberUsernameEnabled()) {
            OMLog.info(TAG, "Remember Username Enabled in Init Config, So lets persist its UI preferences");
            Object remUserUIObj = params
                    .get(OMSecurityConstants.Challenge.REMEMBER_USER_NAME_UI_PREFERENCE_KEY);
            if (remUserUIObj != null) {
                setRememberUsernameUIPrefToStore((Boolean) remUserUIObj);
            } else {
                boolean defaultValue = mConfig.getDefaultValueForRememberUsername();
                OMLog.debug(TAG,
                        "No UI flag for Remember Username found [OM_REMEMBER_USERNAME_PREF] so setting it as default value from init = "
                                + defaultValue);
                setRememberUsernameUIPrefToStore(defaultValue);
            }
        } else {
            OMLog.info(TAG, "Remember Username Not Enabled in the Init Config, Skip persisting of UI preferences");
        }
    }


    /**
     * Stores the remember credentials to the store.
     * Its epected that the UI preferences are already stored before calling this.
     *
     * @param authContext
     */
    void storeRememberCredentialsToStore(OMAuthenticationContext authContext) {
        OMLog.debug(TAG, "storing Remember Credentials to Store");
        boolean autoLoginFromUser = false;
        boolean rememberCredentialsFromUser = false;
        boolean rememberUsernameFromUser = false;
        Map<String, Object> map = authContext.getInputParams();
        // since the storing the UI preference is already taken care [ by the AuthService], If at all the RC feature is enabled in the configuration.
        autoLoginFromUser = (getAutoLoginUIPrefFromStore() == OPTION_SELECTED_BY_USER);
        rememberCredentialsFromUser = (getRememberCredentialsUIPrefFromStore() == OPTION_SELECTED_BY_USER);
        rememberUsernameFromUser = (getRememberUsernameUIPrefFromStore() == OPTION_SELECTED_BY_USER);
        if (autoLoginFromUser || rememberCredentialsFromUser
                || rememberUsernameFromUser) {
            String usernameFromParams = (String) map.get(OMSecurityConstants.Challenge.USERNAME_KEY);
            String passwordFromParams = (String) map.get(OMSecurityConstants.Challenge.PASSWORD_KEY);
            OMCredential credObj = new OMCredential();
            if (!TextUtils.isEmpty(usernameFromParams)) {
                credObj.setUserName(usernameFromParams);
                if (autoLoginFromUser || rememberCredentialsFromUser) {
                    if (!TextUtils.isEmpty(passwordFromParams)) {
                        credObj.setUserPassword(passwordFromParams);
                    }
                }
            }

            // We are using it now.
            // in future we may have to replay identity domain as well
            String tenantName = (String) map.get(OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY);
            if (!TextUtils.isEmpty(tenantName)) {
                credObj.setIdentityDomain(tenantName);
            }
            OMLog.debug(TAG,
                    "Storing Remembered Credentials!!");
            storeCredentialsToStore(credObj);
        } else {
            OMLog.info(TAG, "Remember Credentials Not stored,");
            // since in this request there is nothing selected from the UI now
            // remove credentials and other user preferences
            // this may happen in case of auto login so have a check here too .
            // other wise auto login credentials and flags will be wiped off and
            // auto login will fail in subsequent authentication .
            if (!(getAutoLoginUIPrefFromStore() == OPTION_SELECTED_BY_USER)) {
                removeRememberedCredentialsFromStore();
            }

        }


    }


    public Map<String, Object> getRememberCredentialsChallengeFields() {
        OMLog.debug(TAG, "Getting Remember Credential preferences for Challenge");
        Map<String, Object> map = new HashMap<>();
        //update the map UI preferences.

        boolean populateCred = false;
        if (mConfig.isAutoLoginEnabled()) {
            //let us also send this to info to challenge for app convenience.
            map.put(OMMobileSecurityService.OM_PROP_AUTO_LOGIN_ALLOWED, true);
            boolean autoLoginUIPref;
            if (getAutoLoginUIPrefFromStore() != 0) {
                autoLoginUIPref = (getAutoLoginUIPrefFromStore() == 1) ? true : false;
            } else {
                autoLoginUIPref = mConfig.getDefaultValueForAutoLogin();
            }
            OMLog.info(TAG, "AutoLogin UI Pref to application: " + autoLoginUIPref);
            map.put(OMSecurityConstants.Challenge.AUTO_LOGIN_UI_PREFERENCE_KEY, autoLoginUIPref);
            populateCred = true;
        }
        if (mConfig.isRememberUsernameEnabled()) {
            map.put(OMMobileSecurityService.OM_PROP_REMEMBER_USERNAME_ALLOWED, true);//add on.
            boolean rememberUserUIPref;
            if (getRememberUsernameUIPrefFromStore() != 0) {
                rememberUserUIPref = (getRememberUsernameUIPrefFromStore() == 1) ? true : false;
            } else {
                //if nothing is selected yet, lets send back the default value.
                rememberUserUIPref = mConfig.getDefaultValueForRememberUsername();
            }
            OMLog.info(TAG, "Remember Username UI Pref to application: " + rememberUserUIPref);
            map.put(OMSecurityConstants.Challenge.REMEMBER_USER_NAME_UI_PREFERENCE_KEY, rememberUserUIPref);
            populateCred = true;
        }

        if (mConfig.isRememberCredentialsEnabled()) {
            map.put(OMMobileSecurityService.OM_PROP_REMEMBER_CREDENTIALS_ALLOWED, true);
            boolean rememberCredUIPref;
            if (getRememberCredentialsUIPrefFromStore() != 0) {
                rememberCredUIPref = (getRememberCredentialsUIPrefFromStore() == 1) ? true : false;
            } else {
                rememberCredUIPref = mConfig.getDefaultValueForRememberCredentials();
            }
            OMLog.info(TAG, "Remember Cred UI Pref to application: " + rememberCredUIPref);
            map.put(OMSecurityConstants.Challenge.REMEMBER_CREDENTIALS_UI_PREFERENCE_KEY, rememberCredUIPref);
            populateCred = true;
        }

        if (populateCred) {
            OMCredential rememberedCred;
            rememberedCred = retrieveRememberedCredentials();
            if (rememberedCred != null) {
                if (!TextUtils.isEmpty(rememberedCred.getUserName())) {
                    map.put(OMSecurityConstants.Challenge.USERNAME_KEY, rememberedCred.getUserName());
                }
                if (!TextUtils.isEmpty(rememberedCred.getUserPassword())) {
                    //sending obfuscated value in the challenge fields.
                    //TODO don't think this a Good Idea.
                    //For SDK its difficult to maintain the state
                    map.put(OMSecurityConstants.Challenge.PASSWORD_KEY, OBFUSCATED_PWD);
                    //map.put(OMSecurityConstants.Challenge.PASSWORD_KEY, rememberedCred.getUserPassword());//pass encrypted password
                    //for now I am adding a flag as a preference to the app.
                    //If app updates this flags it means we need to consider the new password other wise
                }
                if (mConfig.isCollectIdentityDomain() && !TextUtils.isEmpty(rememberedCred.getIdentityDomain())) {
                    map.put(OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY, rememberedCred.getIdentityDomain());
                }
            }
        }
        return map;
    }

    //returns remembered credential during last successful authentication.
    OMCredential getRememberedCredential() {
        //TODO
        return null;
    }

    /*
   * utility to remove all the stored credentials and user preferences
   */
    public void removeAll() {
        Log.d(TAG, "removeAll");
        removeRememberedCredentialsFromStore();
        removeRememberCredentialsUIPrefsFromStore();
    }

    /*
     * removes the user preferences for the check box . done when Logout(true)
     * is done .
     */
    public void removeRememberCredentialsUIPrefsFromStore() {
        mCredentialStore.remove(mKey + KEY_SUFFIX_AUTO_LOGIN_UI_PREF_BY_USER);
        mCredentialStore.remove(mKey + KEY_SUFFIX_REMEMBER_CREDENTIALS_UI_PREF_BY_USER);
        mCredentialStore.remove(mKey + KEY_SUFFIX_REMEMBER_USERNAME_UI_PREF_BY_USER);
    }


    /*
     * removes the auto login credentials Cleared in following scenarios :-
     * 1)session time out 2)logout 3)login failure if its an auto login
     * authentication.
     */
    public void removeRememberedCredentialsFromStore() {
        String credentialKey = mKey + KEY_SUFFIX_REMEMBER_CREDENTIALS;
        mCredentialStore.deleteCredential(credentialKey);
        Log.d(TAG, "Removed the Remembered credentials from the store");
    }

    public void inValidateRememberedCredentials() {
        OMCredential newCredToBeStored = new OMCredential();
        OMCredential storedCred = retrieveRememberedCredentials();
        if (storedCred != null) {
            newCredToBeStored.setUserName(storedCred.getUserName());
            newCredToBeStored.setIdentityDomain(storedCred
                    .getIdentityDomain());
            newCredToBeStored.setUserPassword(null);
            storeCredentialsToStore(newCredToBeStored);
        }
        OMLog.info(TAG,
                "Invalidated the Remembered credentials from the store");
    }

     /*
     * Retrieves the stored credentials . if password is present , its decrypted
     * and then returned.
     *
     * @return
     */

    public OMCredential retrieveRememberedCredentials() {
        OMLog.debug(TAG, "Trying Retrieving Remembered Credentials.");
        OMCredential rememberedCred = null;
        String credentialKey = mKey + KEY_SUFFIX_REMEMBER_CREDENTIALS;
        rememberedCred = mCredentialStore.getCredential(credentialKey);
        if (rememberedCred != null) {
            OMLog.debug(TAG, "Remembered Credentials Found!");
            String decryptedPassword = rememberedCred.getUserPassword();
            rememberedCred.setUserPassword(decryptedPassword);
        } else {
            OMLog.debug(TAG, "Remembered Credentials Not Found!");
        }
        return rememberedCred;
    }

    /*
     * utility to store the credentials which will be replayed during auto login
     * . also if user has selected remember credentials or remember username
     * from UI. same credentials are updated on the login screen .
     */
    private void storeCredentialsToStore(OMCredential credObj) {
        mCredentialStore.addCredential(mKey + KEY_SUFFIX_REMEMBER_CREDENTIALS,
                credObj);
    }

    /*
  * returns the auto login value from the store. return val 1 -- > user has
  * accepted auto login from UI return val 0 -- > user yet to accept/reject
  * auto login from UI return val -1 -- > user has rejected auto login from
  * UI
  */
    int getAutoLoginUIPrefFromStore() {
        int result;
        result = mCredentialStore.getInt(mKey + KEY_SUFFIX_AUTO_LOGIN_UI_PREF_BY_USER);
        OMLog.info(TAG, "Auto Login UI Pref From Store : " + result);
        return result;
    }

    /*
     * returns the remember credentials value from the store. return val 1 -- >
     * user has accepted remember credentials from UI return val 0 -- > user yet
     * to accept/reject remember credentials from UI return val -1 -- > user has
     * rejected remember credentials from UI
     */
    int getRememberCredentialsUIPrefFromStore() {
        int result;
        result = mCredentialStore.getInt(mKey
                + KEY_SUFFIX_REMEMBER_CREDENTIALS_UI_PREF_BY_USER);
        OMLog.info(TAG, "Remember Credentials UI pref from Store : " + result);
        return result;
    }

    /*
     * returns the remember username value from the store. return val 1 -- >
     * user has accepted remember username from UI return val 0 -- > user yet to
     * accept/reject remember username from UI return val -1 -- > user has
     * rejected remember username from UI
     */
    int getRememberUsernameUIPrefFromStore() {
        int result;
        result = mCredentialStore.getInt(mKey
                + KEY_SUFFIX_REMEMBER_USERNAME_UI_PREF_BY_USER);
        OMLog.info(TAG, "Remember Username UI pref from store : " + result);
        return result;
    }

    /*
  * sets the auto login value from the user to the store value 1 is stored if
  * user selects to auto login other wise -1 is stored
  */
    void setAutoLoginUIPrefToStore(boolean checked) {
        int val = checked ? OPTION_SELECTED_BY_USER : OPTION_UNSELECTED_BY_USER;
        OMLog.info(TAG, "Auto Login Pref to Store : " + val);
        mCredentialStore.putInt(mKey + KEY_SUFFIX_AUTO_LOGIN_UI_PREF_BY_USER, val);
    }

    /*
     * sets the remember credentials value from the user to the store. value 1
     * is stored if user selects remember credentials other wise -1 is stored
     */
    void setRememberCredentialsUIPrefToStore(boolean checked) {
        int val = checked ? OPTION_SELECTED_BY_USER : OPTION_UNSELECTED_BY_USER;
        OMLog.info(TAG, "Remember Credential Pref to Store : " + val);
        mCredentialStore
                .putInt(mKey + KEY_SUFFIX_REMEMBER_CREDENTIALS_UI_PREF_BY_USER, val);
    }

    /*
     * sets the remember username value from the user to the store. value 1 is
     * stored if user selects remember username other wise -1 is stored
     */
    void setRememberUsernameUIPrefToStore(boolean checked) {
        int val = checked ? OPTION_SELECTED_BY_USER : OPTION_UNSELECTED_BY_USER;
        OMLog.info(TAG, "Remember Username Pref to Store : " + val);
        mCredentialStore.putInt(mKey + KEY_SUFFIX_REMEMBER_USERNAME_UI_PREF_BY_USER, val);
    }
}
