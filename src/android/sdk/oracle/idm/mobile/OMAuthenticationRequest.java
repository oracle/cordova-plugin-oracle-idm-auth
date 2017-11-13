/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile;

import java.net.URL;
import java.util.Set;

import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMAuthenticationScheme;
import oracle.idm.mobile.configuration.OMConnectivityMode;

/**
 * This class can be used to override the configuration properties
 * during every authentication. The configuration properties refer
 * to the properties which are used to initialize {@link OMMobileSecurityService}.
 *
 */
public class OMAuthenticationRequest {
//    * TODO - enhance to keep only customizable fields.
    private String mIdDomain;
    private URL mLogoutEndpoint;
    private URL mAuthenticationURL;
    private OAuthAuthorizationGrantType mOAuthGrantType;
    private int mLogoutTimeOut = 0;
    private URL mOAuthTokenEndpoint;
    private Set<String> mOauthScopes;
    private boolean mCollectIdentityDomain;
    private int mRememberCredFlags;//TODO
    private boolean mForceAuthentication;
    private URL mOAuthAuthorizationEndpoint;
    private OMConnectivityMode mConnMode;
    private OMAuthenticationScheme mAuthScheme;

    /**
     * For use with Basic auth
     */
    OMAuthenticationRequest(OMAuthenticationScheme scheme, URL basicAuthUrl, OMConnectivityMode mode, String idDomain, boolean collectIdentityDomain, int flags, boolean forceAuth, int logoutTimeout) {
        this(mode, idDomain, logoutTimeout, null, forceAuth);
        mAuthScheme = scheme;
        mRememberCredFlags = flags;
        mAuthenticationURL = basicAuthUrl;
        mForceAuthentication = forceAuth;
        mCollectIdentityDomain = collectIdentityDomain;
    }

    /**
     * For use with OAuth
     */
    OMAuthenticationRequest(OMAuthenticationScheme scheme, URL oAuthTokenEndpoint, URL oAuthAuthZEndpoint, Set<String> scopes, OAuthAuthorizationGrantType oAuthGrant, OMConnectivityMode mode, String idDomain, boolean collectIdentityDomain, int flags, boolean forceAuth, int logoutTimeout) {
        this(mode, idDomain, logoutTimeout, scopes, forceAuth);
        mAuthScheme = scheme;
        mRememberCredFlags = flags;
        mOAuthGrantType = oAuthGrant;
        mForceAuthentication = forceAuth;
        mCollectIdentityDomain = collectIdentityDomain;
        mOAuthTokenEndpoint = oAuthTokenEndpoint;
        mOAuthAuthorizationEndpoint = oAuthAuthZEndpoint;
        if (oAuthGrant == OAuthAuthorizationGrantType.AUTHORIZATION_CODE
                || oAuthGrant == OAuthAuthorizationGrantType.IMPLICIT) {
            mAuthenticationURL = mOAuthAuthorizationEndpoint;
        } else {
            mAuthenticationURL = mOAuthTokenEndpoint;
        }
    }

    /**
     * For use with Fed auth
     */
    OMAuthenticationRequest(OMAuthenticationScheme scheme, boolean forceAuth, int logoutTimeout) {
        mAuthScheme = scheme;
        mForceAuthentication = forceAuth;
        mLogoutTimeOut = logoutTimeout;
    }


    //This will be invoked when app creates the auth request,
    //So add all the parameters which can be made configurable at authentication time

    OMAuthenticationRequest(OMConnectivityMode mode, String idDomain, int logoutTimeOut, Set<String> scopes, boolean forceAuthentication) {
        mConnMode = mode;
        mIdDomain = idDomain;
        mLogoutTimeOut = logoutTimeOut;
        mOauthScopes = scopes;
        mForceAuthentication = forceAuthentication;
    }

    public static final class Builder {

        private String nOAuthClientID;
        private String nIdDomain;
        private URL nLogoutEndpoint;
        private int nLogoutTimeout = 0;//TODO
        private OAuthAuthorizationGrantType nOAuthGrantType;
        private URL nBasicAuthEndpoint;
        private URL nOAuthTokenEndpoint;
        private Set<String> nOauthScopes;
        private boolean nCollectIdentityDomain;
        private String nOAuthClientSecret;
        private int nRememberCredFlags = 0;//TODO
        private boolean nForcedAuthentication;
        private URL nOAuthAuthorizationEndpoint;
        private OMConnectivityMode nConnMode;
        private OMAuthenticationScheme nAuthScheme;


        public Builder() {

        }

        public Builder setAuthScheme(OMAuthenticationScheme scheme) {
            nAuthScheme = scheme;
            return this;
        }

        public Builder setOAuthTokenEndpoint(URL oAuthTokenEndpoint) {
            this.nOAuthTokenEndpoint = oAuthTokenEndpoint;
            return this;
        }

        public Builder setOAuthAuthorizationEndpoint(URL oAuthAuthorizationEndpoint) {
            this.nOAuthAuthorizationEndpoint = oAuthAuthorizationEndpoint;
            return this;
        }

        public Builder setOAuthClientID(String clientID) {
            this.nOAuthClientID = clientID;
            return this;
        }

        public Builder setOAuthClientSecret(String clientSecret) {
            this.nOAuthClientSecret = clientSecret;
            return this;
        }

        public Builder setRememberCredFlags(int rememberCredFlags) {
            this.nRememberCredFlags = rememberCredFlags;
            return this;
        }

        public Builder setBasicAuthEndpoint(URL url) {
            nBasicAuthEndpoint = url;
            return this;
        }

        public Builder setCollectIdentityDomain(boolean collectIdentityDomain) {
            this.nCollectIdentityDomain = collectIdentityDomain;
            return this;
        }

        public Builder setOAuthGrantType(OAuthAuthorizationGrantType grantType) {
            this.nOAuthGrantType = grantType;
            return this;
        }

        //used internally by SDK
        OMAuthenticationRequest buildComplete() {
            if (nAuthScheme == null) {
                throw new IllegalArgumentException("OMAuthenticationScheme can not be null");
            }
            switch (nAuthScheme) {
                case BASIC:
                    return new OMAuthenticationRequest(nAuthScheme, nBasicAuthEndpoint, nConnMode, nIdDomain, nCollectIdentityDomain, nRememberCredFlags, nForcedAuthentication, nLogoutTimeout);
                case OAUTH20:
                    return new OMAuthenticationRequest(nAuthScheme, nOAuthTokenEndpoint, nOAuthAuthorizationEndpoint, nOauthScopes, nOAuthGrantType, nConnMode, nIdDomain, nCollectIdentityDomain, nRememberCredFlags, nForcedAuthentication, nLogoutTimeout);
                case FEDERATED:
                case CBA:
                case OPENIDCONNECT10:
                    return new OMAuthenticationRequest(nAuthScheme, nForcedAuthentication, nLogoutTimeout);
            }
            return null;
        }


        public Builder setOAuthScopes(Set<String> oauthScopes) {
            this.nOauthScopes = oauthScopes;
            return this;
        }

        public Builder setIdentityDomain(String name) {
            this.nIdDomain = name;
            return this;
        }


        public Builder setForceAuthentication(boolean forceAuthentication) {
            this.nForcedAuthentication = forceAuthentication;
            return this;
        }


        public Builder setConnMode(OMConnectivityMode connMode) {
            this.nConnMode = connMode;
            return this;
        }

        public Builder setLogoutTimeout(int logoutTimeout) {
            this.nLogoutTimeout = logoutTimeout;
            return this;
        }

        //will be invoked by app.
        public OMAuthenticationRequest build() {
            return new OMAuthenticationRequest(nConnMode, nIdDomain, nLogoutTimeout, nOauthScopes, nForcedAuthentication);
        }
    }

    public OMAuthenticationScheme getAuthScheme() {
        return mAuthScheme;
    }

    public int getLogoutTimeout() {
        return mLogoutTimeOut;
    }

    public URL getAuthenticationURL() {
        return mAuthenticationURL;
    }

    public OMConnectivityMode getConnectivityMode(){
        return mConnMode;
    }

    public void setConnectivityMode(OMConnectivityMode connectivityMode){
        this.mConnMode = connectivityMode;
    }

    public URL getOAuthTokenEndpoint() {
        return mOAuthTokenEndpoint;
    }

    public URL getOAuthAuthorizationEndpoint() {
        return mOAuthAuthorizationEndpoint;
    }

    public OAuthAuthorizationGrantType getOAuthzGrantType() {
        return mOAuthGrantType;
    }

    public Set<String> getOAuthScopes() {
        return mOauthScopes;
    }

    public String getIdentityDomain() {
        return mIdDomain;
    }

    public boolean isForceAuthentication() {
        return mForceAuthentication;
    }
}
