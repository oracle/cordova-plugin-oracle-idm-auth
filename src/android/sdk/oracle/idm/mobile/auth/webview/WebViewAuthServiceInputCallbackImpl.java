/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

package oracle.idm.mobile.auth.webview;

import android.os.Build;
import android.webkit.WebView;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.auth.ASMInputController;
import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.AuthenticationServiceManager;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.logging.OMLog;

/**
 * This is used as the default AuthServiceInputCallback implementation for all authentication mechanisms using WebView.
 * e.g: Federated / OAuth 3-legged
 *
 * @since 11.1.2.3.1
 */
public class WebViewAuthServiceInputCallbackImpl implements AuthServiceInputCallback {
    private static final String TAG = WebViewAuthServiceInputCallbackImpl.class.getSimpleName();
    private AuthenticationServiceManager asm;
    private ASMInputController asmInputController;

    public WebViewAuthServiceInputCallbackImpl(AuthenticationServiceManager asm, ASMInputController asmInputController) {
        this.asm = asm;
        this.asmInputController = asmInputController;
    }

    @Override
    public void onInput(final Map<String, Object> inputs) {
        asmInputController.onInputAvailable(inputs);
    }

    @Override
    public void onError(final OMErrorCode error) {
        OMLog.debug(TAG, "onError");
//        cleanUp();
        asmInputController.onInputError(error);
    }

    @Override
    public void onCancel() {
        OMLog.debug(TAG, "onCancel");
        /*It is not possible to delete cookies specific to an authentication attempt using webview.
        * The option of deleting all session cookies is ruled out as it will other MAF features in
        * a single app.
        *
        * Client cert preferences are also not cleared because the use-case mentioned in cleanUp()
        * is a remote use-case.
        * */
//        cleanUp();
        asmInputController.onCancel();
    }

    private void cleanUp() {
        OMCookieManager.getInstance().removeSessionCookies(asm.getApplicationContext());
            /* Client cert preferences are cleared because of the following use-case:
            * 1. Client cert challenge comes first. User selects one.
            * 2. Untrusted server cert challenge comes next. User presses cancel.
             *
             * In this use-case, the client cert preferences MUST be cleared so that when user tries to
             * authenticate again, the client cert prompt comes up.
            * */
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            WebView.clearClientCertPreferences(new Runnable() {
                @Override
                public void run() {
                    OMLog.debug(TAG, "ClientCertPreferences cleared");
                }
            });
        }
    }
}
