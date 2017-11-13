/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.openID;

import android.text.TextUtils;

import java.util.Map;

import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.SESSION_EXPIRY;
import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.SUBJECT;
import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.USER_DISPLAY_NAME;
import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.USER_ID;
import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.USER_LANG;
import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.USER_LOCAL;
import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.USER_TENANT_NAME;
import static oracle.idm.mobile.auth.openID.OpenIDToken.TokenClaims.USER_TIMEZONE;


/**
 * Contains the user info for the Open ID user
 */
public class OpenIDUserInfo {

    private static final String TAG = OpenIDUserInfo.class.getSimpleName();

    private Map<String, Object> mClaims;
    private String mUserID;
    private String mUsername;
    private String mUserDOB;
    private String mUserLang;
    private String mUserTimeZone;
    private String mUserLocale;
    private String mDisplayName;
    private String mUserTenantName;
    private String mSubject;
    private String mSubjectMapAttribute;
    private long mSessionExpTime;

    /**
     * @param claims
     */
    OpenIDUserInfo(Map<String, Object> claims) {
        mClaims = claims;
        populate();
    }

    private void populate() {
        mUserTimeZone = (String) mClaims.get(USER_TIMEZONE.getName());
        mSubject = (String) mClaims.get(SUBJECT.getName());
        mUserLocale = (String) mClaims.get(USER_LOCAL.getName());
        mDisplayName = (String) mClaims.get(USER_DISPLAY_NAME.getName());
        mUserTenantName = (String) mClaims.get(USER_TENANT_NAME.getName());
        mUserID = (String) mClaims.get(USER_ID.getName());
        mSessionExpTime = (long) mClaims.get(SESSION_EXPIRY.getName());
        mUserLang = (String) mClaims.get(USER_LANG.getName());
    }

    public String getSubjectMapAttribute() {
        return mSubjectMapAttribute;
    }

    public String getUserSubject() {
        return mSubject;
    }


    public String getUserID() {
        return mUserID;
    }

    public String getUsername() {
        if (TextUtils.isEmpty(mUsername)) {
            return mSubject;
        }
        return mUsername;
    }

    public String getUserDOB() {
        return mUserDOB;
    }

    public String getUserLang() {
        return mUserLang;
    }

    public String getUserTimeZone() {
        return mUserTimeZone;
    }

    public String getUserLocale() {
        return mUserLocale;
    }

    public String getDisplayName() {
        return mDisplayName;
    }

    public String getUserTenantName() {
        return mUserTenantName;
    }

    public long getSessionExpTime() {
        return mSessionExpTime;
    }


    public String toString() {
        StringBuilder sb = new StringBuilder("userInfo : {");
        sb.append("user_id:" + mUserID);
        sb.append(",user_tz:" + mUserTimeZone);
        sb.append(",user_locale:" + mUserLocale);
        sb.append(",sub:" + mSubject);
        sb.append(",subMapAttr:" + mSubjectMapAttribute);
        sb.append("}");
        return sb.toString();
    }
}
