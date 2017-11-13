/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.webview;

import java.util.Map;

import oracle.idm.mobile.auth.AuthServiceInputCallback;

/**
 * This interface is to define the contract to be followed for configuring the webview used for authentication.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public interface WebViewConfigurationHandler {

    /**
     * Configures the WebView instance passed in inputParams.
     *
     * @param inputParams MUST contain OMSecurityConstants.Challenge.WEBVIEW_KEY -> WebView instance
     * @param callback
     */
    void configureView(Map<String, Object> inputParams,
                       final AuthServiceInputCallback callback);

}
