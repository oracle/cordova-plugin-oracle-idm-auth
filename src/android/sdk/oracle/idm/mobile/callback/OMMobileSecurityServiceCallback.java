/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.callback;

import android.os.Handler;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.auth.OMAuthenticationChallenge;
import oracle.idm.mobile.auth.OMAuthenticationCompletionHandler;
import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;

/**
 * OMMobileSecurityServiceCallback is a callback interface to be implemented by the application to receive result events after performing operations on @Link OMMobileSecurityService.
 *
 */
//TODO documentation for each callback
public interface OMMobileSecurityServiceCallback {

    void onSetupCompleted(OMMobileSecurityService mss, OMMobileSecurityConfiguration config, OMMobileSecurityException mse);

    void onAuthenticationChallenge(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, OMAuthenticationCompletionHandler completionHandler);

    void onAuthenticationCompleted(OMMobileSecurityService mss, OMAuthenticationContext authContext, OMMobileSecurityException mse);

    void onLogoutChallenge(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, OMLogoutCompletionHandler completionHandler);

    void onLogoutCompleted(OMMobileSecurityService mss, OMMobileSecurityException mse);

    Handler getHandler();

}
