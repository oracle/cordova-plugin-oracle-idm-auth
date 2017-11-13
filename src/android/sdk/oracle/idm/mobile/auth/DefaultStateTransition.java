/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.util.Log;

import java.util.HashMap;
import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMAuthenticationScheme;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.auth.OAuthConnectionsUtil.OAuthType;

import static oracle.idm.mobile.OMSecurityConstants.Param.COLLECT_OFFLINE_CREDENTIAL;

/**
 * This is SDK's default implementation of the {@link AuthStateTransition}
 * interface which handles populating the {@link OMAuthenticationContext}
 * instance fields passed to it, as well as determining the next step in the
 * authentication process cycle.
 *
 */
class DefaultStateTransition implements AuthStateTransition {

    private AuthenticationServiceManager mASM;
    //mapping which contains intial authentication state for each authentication scheme.
    private Map<OMAuthenticationScheme, AuthenticationService.Type> mInitialState;

    public DefaultStateTransition(AuthenticationServiceManager asm) {
        this.mASM = asm;

        mInitialState = new HashMap<>();

        mInitialState.put(OMAuthenticationScheme.BASIC,
                AuthenticationService.Type.BASIC_SERVICE);
        mInitialState.put(OMAuthenticationScheme.OFFLINE,
                AuthenticationService.Type.OFFLINE_SERVICE);
        mInitialState.put(OMAuthenticationScheme.FEDERATED,
                AuthenticationService.Type.FED_AUTH_SERVICE);
        mInitialState.put(OMAuthenticationScheme.CBA,
                AuthenticationService.Type.CBA_SERVICE);

        mInitialState.put(OMAuthenticationScheme.OPENIDCONNECT10, asm.isClientRegistrationRequired() ?
                AuthenticationService.Type.CLIENT_REGISTRATION_SERVICE :
                AuthenticationService.Type.OPENIDCONNECT10);


        if (asm.getOAuthConnectionsUtil() != null) {
            if (asm.getOAuthConnectionsUtil().getOAuthType() == OAuthType.MSOAUTH) {
                // if it is mobile and social OAuth then the initial state is
                // the acquisition of pre authZ code for client registration.
                mInitialState.put(OMAuthenticationScheme.OAUTH20,
                        AuthenticationService.Type.OAUTH_MS_PREAUTHZ);
            } else {
                mInitialState.put(OMAuthenticationScheme.OAUTH20, asm.isClientRegistrationRequired() ?
                        AuthenticationService.Type.CLIENT_REGISTRATION_SERVICE :
                        AuthenticationService.Type.OAUTH20_RO_SERVICE);
            }
        }
    }


    @Override
    public AuthenticationService doStateTransition(OMHTTPResponse toBeProcessedFurther,
                                                   OMAuthenticationContext authContext)
            throws OMMobileSecurityException {
        if (authContext != null && authContext.getStatus() == OMAuthenticationContext.Status.SUCCESS) {
            Log.i(OMSecurityConstants.TAG, "[DefaultStateTransition] doStateTransition - authContext status is SUCCESS return null");
            return null;
        }
        if (authContext != null && toBeProcessedFurther == null) {

            OMLog.info(OMSecurityConstants.TAG, "[DefaultStateTransition] doStateTransition " + authContext.getStatus());
            if (authContext.getStatus() == OMAuthenticationContext.Status.IN_PROGRESS) {
                // This is self authentication use case for any app
                return getAuthenticationService(authContext
                        .getAuthRequest().getAuthScheme());
            } else if (authContext.getStatus() == OMAuthenticationContext.Status.COLLECT_OFFLINE_CREDENTIALS) {
                //means offline services detects to collect credentials
                authContext.getInputParams().put(COLLECT_OFFLINE_CREDENTIAL, true);
                return mASM
                        .getAuthService(AuthenticationService.Type.OFFLINE_SERVICE);
            } else if (authContext.getStatus() == OMAuthenticationContext.Status.INITIAL_VALIDATION_DONE) {
                authContext.setStatus(OMAuthenticationContext.Status.IN_PROGRESS);
                return getAuthenticationService(authContext
                        .getAuthRequest().getAuthScheme());

            } else if (authContext.getStatus() == OMAuthenticationContext.Status.OAUTH_PRE_AUTHZ_DONE) {
                authContext.setStatus(OMAuthenticationContext.Status.OAUTH_DYCR_IN_PROGRESS);
                return mASM.getAuthService(AuthenticationService.Type.OAUTH_MS_DYCR);
            } else if (authContext.getStatus() == OMAuthenticationContext.Status.OAUTH_DYCR_DONE) {
                authContext.setStatus(OMAuthenticationContext.Status.IN_PROGRESS);
                return mASM.getAuthService(AuthenticationService.Type.OAUTH20_RO_SERVICE);
            } else if (authContext.getStatus() == OMAuthenticationContext.Status.OAUTH_IDCS_CLIENT_REGISTRATION_DONE) {
                authContext.setStatus(OMAuthenticationContext.Status.IN_PROGRESS);
                return mASM.getAuthService(AuthenticationService.Type.OAUTH20_RO_SERVICE);
            } else if (authContext.getStatus() == OMAuthenticationContext.Status.OPENID_IDCS_CLIENT_REGISTRATION_DONE) {
                authContext.setStatus(OMAuthenticationContext.Status.IN_PROGRESS);
                return mASM.getAuthService(AuthenticationService.Type.OPENIDCONNECT10);
            } else if (authContext.getStatus() == OMAuthenticationContext.Status.OPENID_IDCS_CLIENT_REGISTRATION_IN_PROGRESS
                    || authContext.getStatus() == OMAuthenticationContext.Status.OAUTH_IDCS_CLIENT_REGISTRATION_IN_PROGRESS) {
                return mASM.getAuthService(AuthenticationService.Type.CLIENT_REGISTRATION_SERVICE);
            }
        }
        //TODO do this basic of state alone should be dependent on the response
        //respective authentication service will populate
        //handle for authentication services which have a response in the result.
        //FOR KBA and other authentication, update as in when required.
        return null;
    }

    @Override
    public AuthenticationService getAuthenticationService(
            OMAuthenticationScheme authScheme) throws OMMobileSecurityException {
        if (authScheme == null) {
            throw new OMMobileSecurityException(
                    OMErrorCode.INVALID_AUTHENTICATION_SCHEME);
        }

        AuthenticationService.Type initialAuthServiceName;
        if (mASM.getMSS().getMobileSecurityConfig().getAuthenticationScheme() == OMAuthenticationScheme.OAUTH20) {
            initialAuthServiceName = mASM.getOAuthServiceType();
            if (initialAuthServiceName == null) {
                throw new OMMobileSecurityException(
                        OMErrorCode.INTERNAL_ERROR);
            } else if (initialAuthServiceName == AuthenticationService.Type.OAUTH20_RO_SERVICE && authScheme == OMAuthenticationScheme.OFFLINE) {
                initialAuthServiceName = AuthenticationService.Type.OFFLINE_SERVICE;
            } else if (initialAuthServiceName == AuthenticationService.Type.OAUTH20_RO_SERVICE && mASM.getOAuthConnectionsUtil().getOAuthType() == OAuthType.MSOAUTH) {
                initialAuthServiceName = AuthenticationService.Type.OAUTH_MS_PREAUTHZ;
            }
        } else {
            initialAuthServiceName = mInitialState
                    .get(authScheme);
        }

        return mASM
                .getAuthService(initialAuthServiceName);
    }

    @Override
    public AuthenticationService getInitialState(
            OMAuthenticationRequest authRequest)
            throws OMMobileSecurityException {
        //TODO revisit when the configuration is added.
        if (mASM.getMSS().getMobileSecurityConfig().isOfflineAuthenticationAllowed()) {
            return getAuthenticationService(OMAuthenticationScheme.OFFLINE);
        } else {
            AuthenticationService authService = getAuthenticationService(authRequest.getAuthScheme());
            Log.i(OMSecurityConstants.TAG, "[DefaultStateTransition] getInitialState authScheme : " + authRequest.getAuthScheme() + " TYPE : " + authService.getType());
            return authService;
        }
    }

    @Override
    public AuthenticationService getLogoutState(AuthenticationService authService) {
        OMMobileSecurityConfiguration config = mASM.getMSS().getMobileSecurityConfig();
        OMAuthenticationScheme authScheme = config.getAuthenticationScheme();

        if (authService == null) {
            if (mASM.getOAuthConnectionsUtil() != null && mASM.getOAuthConnectionsUtil().getOAuthType() == OAuthType.MSOAUTH) {
                return mASM.getAuthService(AuthenticationService.Type.OAUTH_MS_DYCR);
            }
            if (authScheme == OMAuthenticationScheme.BASIC) {
                return mASM.getAuthService(AuthenticationService.Type.BASIC_SERVICE);
            } else if ((authScheme == OMAuthenticationScheme.OAUTH20 || authScheme == OMAuthenticationScheme.OPENIDCONNECT10) &&
                    ((OMOAuthMobileSecurityConfiguration) config).isClientRegistrationRequired()) {
                return mASM.getAuthService(AuthenticationService.Type.CLIENT_REGISTRATION_SERVICE);
            } else if (authScheme == OMAuthenticationScheme.OAUTH20) {
                return getOAuthService(mASM.getOAuthConnectionsUtil().getOAuthGrantType());
            } else if (authScheme == OMAuthenticationScheme.CBA) {
                return mASM.getAuthService(AuthenticationService.Type.CBA_SERVICE);
            } else if (authScheme == OMAuthenticationScheme.FEDERATED) {
                return mASM.getAuthService(AuthenticationService.Type.FED_AUTH_SERVICE);
            } else if (authScheme == OMAuthenticationScheme.OPENIDCONNECT10) {
                return mASM.getAuthService(AuthenticationService.Type.OPENIDCONNECT10);
            }
        } else if (!(authService instanceof OfflineAuthenticationService) && config.isOfflineAuthenticationAllowed()) {
            return mASM.getAuthService(AuthenticationService.Type.OFFLINE_SERVICE);
        } else if ((authService instanceof OAuthMSDYCRService)) {
            return mASM.getAuthService(AuthenticationService.Type.OAUTH20_RO_SERVICE);
        } else if (authService instanceof IDCSClientRegistrationService) {
            //could be an open ID or OAuth use case
            if (authScheme == OMAuthenticationScheme.OAUTH20) {
                return getOAuthService(mASM.getOAuthConnectionsUtil().getOAuthGrantType());
            } else if (authScheme == OMAuthenticationScheme.OPENIDCONNECT10) {
                return mASM.getAuthService(AuthenticationService.Type.OPENIDCONNECT10);
            }
        }
        return null;
    }

    private AuthenticationService getOAuthService(OAuthAuthorizationGrantType grant) {
        switch (mASM.getOAuthConnectionsUtil().getOAuthGrantType()) {
            case AUTHORIZATION_CODE:
                return mASM.getAuthService(AuthenticationService.Type.OAUTH20_AC_SERVICE);
            case RESOURCE_OWNER:
                return mASM.getAuthService(AuthenticationService.Type.OAUTH20_RO_SERVICE);
            case CLIENT_CREDENTIALS:
                return mASM.getAuthService(AuthenticationService.Type.OAUTH20_CC_SERVICE);
        }
        return null;
    }

    public AuthenticationService getCancelState(AuthenticationService authService) {
        OMMobileSecurityConfiguration config = mASM.getMSS().getMobileSecurityConfig();
        OMAuthenticationScheme authScheme = config.getAuthenticationScheme();

        if (authService == null && config.isOfflineAuthenticationAllowed()) {
            return mASM.getAuthService(AuthenticationService.Type.OFFLINE_SERVICE);
        } else if (authService == null || authService instanceof OfflineAuthenticationService) {
            if (authScheme == OMAuthenticationScheme.BASIC) {
                return mASM.getAuthService(AuthenticationService.Type.BASIC_SERVICE);
            } else if (authScheme == OMAuthenticationScheme.OAUTH20) {
                switch (mASM.getOAuthConnectionsUtil().getOAuthGrantType()) {
                    case AUTHORIZATION_CODE:
                        return mASM.getAuthService(AuthenticationService.Type.OAUTH20_AC_SERVICE);
                    case RESOURCE_OWNER:
                        return mASM.getAuthService(AuthenticationService.Type.OAUTH20_RO_SERVICE);
                    case CLIENT_CREDENTIALS:
                        return mASM.getAuthService(AuthenticationService.Type.OAUTH20_CC_SERVICE);
                }
            } else if (authScheme == OMAuthenticationScheme.CBA) {
                return mASM.getAuthService(AuthenticationService.Type.CBA_SERVICE);
            } else if (authScheme == OMAuthenticationScheme.FEDERATED) {
                return mASM.getAuthService(AuthenticationService.Type.FED_AUTH_SERVICE);
            }
        }
        return null;
    }
}
