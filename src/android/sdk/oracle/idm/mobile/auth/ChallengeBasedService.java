/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;

/**
 * Should be implemented by authentication services which require application/user input to process.
 */
interface ChallengeBasedService {

    OMAuthenticationChallenge createLoginChallenge() throws OMMobileSecurityException;

    OMAuthenticationChallenge createLogoutChallenge();

    boolean isChallengeInputRequired(Map<String, Object> inputParams);

    OMAuthenticationCompletionHandler getCompletionHandlerImpl();

}
