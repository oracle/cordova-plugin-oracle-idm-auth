/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * This represents the authentication challenge which should be
 * responded to complete the authentication process.
 *
 * @see  OMAuthenticationChallengeType
 */
public class OMAuthenticationChallenge {


    private static final String REQUIRED_TYPE = "required";

    protected OMAuthenticationChallengeType mChallengeType;
    protected Map<String, Object> mChallengeFields;

    /**
     *
     * @param type
     * @hide
     */
    public OMAuthenticationChallenge(OMAuthenticationChallengeType type) {
        mChallengeType = type;
    }

    /**
     *
     * @param key
     * @param type
     * @hide
     */
    public void addChallengeField(String key, Object type) {
        if (!TextUtils.isEmpty(key)) {
            getChallengeFields().put(key, type);
        }
    }

    void addChallengeFields(final Map<String, Object> challengeFields) {
        getChallengeFields().putAll(challengeFields);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("type : ");
        sb.append(mChallengeType.name());
        if (mChallengeFields != null && !mChallengeFields.isEmpty()) {
            sb.append(",");
            sb.append(mChallengeFields);
        }
        return sb.toString();
    }

    /**
     * This represents the type of authentication challenge
     * to be handled by the app/user.
     *
     * @return
     */
    public OMAuthenticationChallengeType getChallengeType() {
        return mChallengeType;
    }

    /**
     * This represents the fields which will give additional information about
     * the authentication challenge to be completed. Refer {@link oracle.idm.mobile.OMSecurityConstants.Challenge}
     * for the available keys with which additional information will be given.
     *
     * @return
     */
    public  Map<String, Object> getChallengeFields() {
        if (mChallengeFields == null) {
            mChallengeFields = new HashMap<>();
        }
        return mChallengeFields;
    }


}
