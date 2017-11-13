/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;


import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.configuration.OMAuthenticationScheme;
import oracle.idm.mobile.connection.OMHTTPResponse;


/**
 * OMStateTransition is an interface which can be implemented by calling
 * application for determining the next step in the authentication process as
 * well to populate the {@link OMAuthenticationContext} with the values from the
 * previous response.
 *
 */
interface AuthStateTransition {
    /**
     * This method populates the {@link OMAuthenticationContext} fields with the
     * values form the response string input and determines the next step in the
     * authentication process cycle.
     *
     * @param response      response from the previous request.
     * @param authContext an instance of {@link OMAuthenticationContext}
     * @return {@link AuthenticationService} instance
     * @throws OMMobileSecurityException if there is any exception
     */
    AuthenticationService doStateTransition(OMHTTPResponse response,
                                            OMAuthenticationContext authContext)
            throws OMMobileSecurityException;

    /**
     * This method returns authentication service instances for the given
     * authentication service scheme
     *
     * @param authScheme
     * @return {@link AuthenticationService} instances
     * @throws OMMobileSecurityException
     */
    AuthenticationService getAuthenticationService(
            OMAuthenticationScheme authScheme) throws OMMobileSecurityException;

    /**
     * This method returns the initial authentication service to start the
     * authentication process.
     *
     * @param authRequest an instance of {@link OMAuthenticationRequest}
     * @return {@link AuthenticationService} instance
     */

    AuthenticationService getInitialState(OMAuthenticationRequest authRequest)
            throws OMMobileSecurityException;

    /**
     * This method returns the next authentication service to be invoked in the
     * sequence of logout requested by the calling application
     *
     * @param authService an instance of {@link AuthenticationService} or null for the
     *                    first request.
     * @return an instance of {@link AuthenticationService}
     */
    AuthenticationService getLogoutState(AuthenticationService authService);

    /**
     * This method returns the next authentication service to be invoked in the
     * sequence of cancel requested by the calling application
     *
     * @param authService an instance of {@link AuthenticationService} or null for the
     *                    first request.
     * @return an instance of {@link AuthenticationService}
     */
    AuthenticationService getCancelState(AuthenticationService authService);
}
