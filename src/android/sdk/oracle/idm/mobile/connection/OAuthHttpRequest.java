/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.net.URL;
import java.util.Set;

/**
 * Internal class to represent the OAuth Resource request
 *
 * @since 11.1.2.3.1
 */
class OAuthHttpRequest extends OMHTTPRequest {


    private Set<String> mScopes;

    public OAuthHttpRequest(URL url, Method method) {
        super(url, method);
    }


    public URL getResourceURL() {
        return mResourceURL;
    }

    public void setResourceURL(URL mResourceURL) {
        this.mResourceURL = mResourceURL;
    }

    public Method getMethod() {
        return mMethod;
    }

    public void setMethod(Method mMethod) {
        this.mMethod = mMethod;
    }

    public Set<String> getScopes() {
        return mScopes;
    }

    public void setScopes(Set<String> scopes) {
        this.mScopes = scopes;
    }


}
