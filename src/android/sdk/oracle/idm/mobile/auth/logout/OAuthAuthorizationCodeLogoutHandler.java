/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.logout;

import android.net.Uri;
import android.webkit.WebView;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.OAuthConnectionsUtil;
import oracle.idm.mobile.auth.OMAuthenticationChallenge;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;

/**
 * Handler returned to the application to complete the logout flow for OAuth Authorization code grant.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class OAuthAuthorizationCodeLogoutHandler extends OMLogoutCompletionHandler {

    private static final String TAG = OAuthAuthorizationCodeLogoutHandler.class.getSimpleName();
    private OMMobileSecurityServiceCallback mAppCallback;
    private OMMobileSecurityConfiguration.BrowserMode mBrowserMode;
    private String mState;
    private AuthServiceInputCallback mAuthServiceCallback;
    private boolean isProceededOrCanceled = false;

    public OAuthAuthorizationCodeLogoutHandler(OMMobileSecurityConfiguration.BrowserMode browserMode, String state,
                                               OMMobileSecurityServiceCallback applicationCallback) {
        OMLog.info(TAG, "initialized OAuthAuthZCodeLogoutHandler: " + browserMode);
        mAppCallback = applicationCallback;
        mBrowserMode = browserMode;
        mState = state;
    }

    @Override
    public void createLogoutChallengeRequest(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        OMLog.info(TAG, "createLogoutChallengeRequest");
        mAuthServiceCallback = authServiceCallback;
        mAppCallback.onLogoutChallenge(mss, challenge, this);
    }

    @Override
    public void proceed(Map<String, Object> responseFields) {
        OMLog.info(TAG, "proceed()- application is interested in handling the logout URL!");
        isProceededOrCanceled = true;
        try {
            validateResponseFields(responseFields);
            mAuthServiceCallback.onInput(responseFields);
        } catch (OMMobileSecurityException e) {
            OMLog.info(TAG, "proceed()" + e.getErrorMessage());
            mAuthServiceCallback.onError(e.getError());
        }
    }

    @Override
    void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {
        if (mBrowserMode == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
            if (responseFields != null) {
                Object view = responseFields.get(OMSecurityConstants.Challenge.WEBVIEW_KEY);
                if (view instanceof WebView) {
                    return;
                }
            }
            throw new OMMobileSecurityException(OMErrorCode.INVALID_CHALLENGE_INPUT_RESPONSE);
            //though we need webview client as well but we not making it mandatory
        } else {
            //for external browser there is nothing to check, we simply assume that the app might have invoked the URL at their end
            // Optionally, they can pass REDIRECT_RESPONSE_KEY in case of IDCS logout.
            Object redirectResponse = responseFields.get(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY);
            Uri redirectResponseUri = null;
            if (redirectResponse instanceof String) {
                redirectResponseUri = Uri.parse((String) redirectResponse);
            } else if (redirectResponse instanceof Uri) {
                redirectResponseUri = (Uri) redirectResponse;
            }
            if (redirectResponseUri != null) {
                String query = redirectResponseUri.getEncodedQuery();
                if (query != null) {
                    String state = redirectResponseUri.getQueryParameter(OAuthConnectionsUtil.OAuthResponseParameters.STATE.getValue());
                    if (state == null || !state.equals(mState)) {
                        OMLog.error(TAG, "Invalid state recovered from the response.");
                        throw new OMMobileSecurityException(OMErrorCode.OAUTH_STATE_INVALID);
                    }
                }
            }
        }
    }

    @Override
    public void cancel() {
        OMLog.info(TAG, "cancel()- application not interested in handling the logout URL!");
        isProceededOrCanceled = true;
        mAuthServiceCallback.onCancel();
    }

    public boolean isProceededOrCanceled() {
        return isProceededOrCanceled;
    }
}
