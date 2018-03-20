/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.idm.auth.plugin;

import java.util.HashMap;
import java.util.Map;

import android.content.res.Resources;
import android.view.View;
import android.widget.Button;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import oracle.idm.mobile.logging.OMLog;

/**
 * Activity containing a webView which is used to address IDM's authentication flows that needs an embedded WebView.
 */
public class WebViewActivity extends Activity
{
  public static final String FINISH_WEB_VIEW_INTENT = "finishWebView";
  public static final String CANCEL_WEB_VIEW_INTENT = "cancelFromWebView";

  private String redirectEndPoint;

  @Override
  protected void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    Resources resources = getApplication().getResources();
    String packageName = getApplication().getPackageName();
    redirectEndPoint = getIntent().getStringExtra(OMMobileSecurityService.OM_PROP_OAUTH_REDIRECT_ENDPOINT);
    setContentView(resources.getIdentifier(_ACTIVITY_WEB_VIEW, _LAYOUT, packageName));
    _webView = (WebView) findViewById(resources.getIdentifier(_IDM_WEB_VIEW, _ID, packageName));
    _webView.getSettings().setJavaScriptEnabled(true);
    _webView.getSettings().setDomStorageEnabled(true);

    getActionBar().hide();

    IdmAuthentication.CompletionHandler completionHandler = IdmAuthentication.getCompletionHandler();
    final IdmAuthentication.CompletionHandler.CHALLENGE_TYPE challengeType = completionHandler.getChallengeType();

    final Button backBtn = _getBackButton(resources, packageName);
    final Button forwardBtn = _getForwardButton(resources, packageName);
    final Button reloadBtn = _getReloadButton(resources, packageName);
    final Button cancelBtn = _getCancelButton(resources, packageName, challengeType);

    _webViewClient = _createWebViewClient(challengeType, backBtn, forwardBtn, reloadBtn, cancelBtn);
    _broadcastReceiver = _createBroadcastReceiver();
    registerReceiver(_broadcastReceiver, new IntentFilter(FINISH_WEB_VIEW_INTENT));

    _proceed(completionHandler);
    OMLog.debug(TAG,"Created webview activity and passed on to IDM SDK.");
  }

  @Override
  protected void onDestroy()
  {
    super.onDestroy();
    unregisterReceiver(_broadcastReceiver);
    OMLog.debug(TAG,"Destroyed webview activity.");
  }

  private void _proceed(IdmAuthentication.CompletionHandler completionHandler)
  {
    Map<String, Object> responseFields = new HashMap<String, Object>();
    responseFields.put(OMSecurityConstants.Challenge.WEBVIEW_KEY, _webView);
    responseFields.put(OMSecurityConstants.Challenge.WEBVIEW_CLIENT_KEY, _webViewClient);
    completionHandler.proceed(responseFields);
  }

  private BroadcastReceiver _createBroadcastReceiver()
  {
    return new BroadcastReceiver()
    {
        @Override
        public void onReceive(Context context, Intent intent)
        {
          String action = intent.getAction();
          if (FINISH_WEB_VIEW_INTENT.equals(action))
          {
            OMLog.debug(TAG, "Finishing the activity.");
            // TODO: Bug 26048182, Destroy the webview once we are done with it.
            finish();
          }
        }
    };
  }

  private WebViewClient _createWebViewClient(final IdmAuthentication.CompletionHandler.CHALLENGE_TYPE challengeType,
                                             final Button backBtn,
                                             final Button forwardBtn,
                                             final Button reloadBtn,
                                             final Button cancelBtn)
  {
    return new WebViewClient()
    {
      @Override
      public boolean shouldOverrideUrlLoading(WebView view, String url) {
        if (redirectEndPoint != null
            && !redirectEndPoint.isEmpty()
            && url.startsWith(redirectEndPoint)) {
          OMLog.debug(TAG,"Finishing webview for OAUTH redirect end point: " + url);
          finish();
        }

        return super.shouldOverrideUrlLoading(view, url);
      }

      @Override
      public void onPageFinished(WebView view, String url)
      {
        // TODO: Bug 26134480
        // This is not getting invoked now. Ideally the buttons should be
        // enabled after page is rendered.
        OMLog.debug(TAG, "WebView is loaded now. Enabling buttons...");
        backBtn.setEnabled(true);
        forwardBtn.setEnabled(true);
        if (challengeType == IdmAuthentication.CompletionHandler.CHALLENGE_TYPE.LOGIN)
        {
          OMLog.debug(TAG,"Enabling cancel button for LOGIN challenge.");
          cancelBtn.setEnabled(true);
        }

        reloadBtn.setEnabled(true);
      }
    };
  }

  private Button _getCancelButton(Resources resources,
                                  String packageName,
                                  IdmAuthentication.CompletionHandler.CHALLENGE_TYPE challengeType)
  {
    Button cancelBtn = (Button) findViewById(resources.getIdentifier(_CANCEL_BTN_ID, _ID, packageName));
    cancelBtn.setOnClickListener(new View.OnClickListener()
    {
      @Override
      public void onClick(View v)
      {
        runOnUiThread(new Runnable()
        {
          @Override
          public void run()
          {
            sendBroadcast(new Intent(CANCEL_WEB_VIEW_INTENT));
          }
        });
      }
    });
    cancelBtn.setEnabled(false);

    if (challengeType == IdmAuthentication.CompletionHandler.CHALLENGE_TYPE.LOGIN)
    {
      OMLog.debug(TAG,"Enabling cancel button for LOGIN challenge.");
      cancelBtn.setEnabled(true);
    }
    return cancelBtn;
  }

  private Button _getReloadButton(Resources resources, String packageName)
  {
    Button reloadBtn = (Button) findViewById(resources.getIdentifier(_RELOAD_BTN_ID, _ID, packageName));
    reloadBtn.setOnClickListener(new View.OnClickListener()
    {
      @Override
      public void onClick(View v)
      {
        _webView.reload();
      }
    });
//    reloadBtn.setEnabled(false);
    return reloadBtn;
  }

  private Button _getForwardButton(Resources resources, String packageName)
  {
    Button forwardBtn = (Button) findViewById(resources.getIdentifier(_FORWARD_BTN_ID, _ID, packageName));
    forwardBtn.setOnClickListener(new View.OnClickListener()
    {
      @Override
      public void onClick(View v)
      {
        if (_webView.canGoForward())
        {
          _webView.goForward();
        }
      }
    });
//    forwardBtn.setEnabled(false);
    return forwardBtn;
  }

  private Button _getBackButton(Resources resources, String packageName)
  {
    Button backBtn = (Button) findViewById(resources.getIdentifier(_BACK_BTN_ID, _ID, packageName));
    backBtn.setOnClickListener(new View.OnClickListener()
    {
      @Override
      public void onClick(View v)
      {
        if (_webView.canGoBack())
        {
          _webView.goBack();
        }
      }
    });
//    backBtn.setEnabled(false);
    return backBtn;
  }

  private WebView _webView;
  private WebViewClient _webViewClient;
  private BroadcastReceiver _broadcastReceiver;

  private static final String TAG = WebViewActivity.class.getSimpleName();
  private static final String _ACTIVITY_WEB_VIEW = "activity_web_view";
  private static final String _ID = "id";
  private static final String _LAYOUT = "layout";
  private static final String _IDM_WEB_VIEW = "idmWebView";
  private static final String _CANCEL_BTN_ID = "webViewCancelBtn";
  private static final String _RELOAD_BTN_ID = "webViewReloadBtn";
  private static final String _FORWARD_BTN_ID = "webViewFwdBtn";
  private static final String _BACK_BTN_ID = "webViewBackBtn";
}
