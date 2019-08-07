/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.idm.auth.plugin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import android.support.v4.content.LocalBroadcastManager;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import oracle.idm.auth.plugin.util.ResourceHelper;
import oracle.idm.mobile.OMSecurityConstants;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * Activity containing a webView which is used to address IDM's authentication flows that needs an embedded WebView.
 */
public class WebViewActivity extends Activity
{
  public static final String FINISH_WEB_VIEW_INTENT = "finishWebView";
  public static final String CANCEL_WEB_VIEW_INTENT = "cancelFromWebView";
  public static final String BUTTONS_WEB_VIEW_PROP = "buttonsAvailable";

  @Override
  protected void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    setContentView(_R.getLayout(_ACTIVITY_WEB_VIEW));
    _webView = (WebView) findViewById(_R.getIdentifier(_IDM_WEB_VIEW));
    _webView.getSettings().setJavaScriptEnabled(true);
    _webView.getSettings().setDomStorageEnabled(true);

    getActionBar().hide();

    IdmAuthentication.CompletionHandler completionHandler = IdmAuthentication.getCompletionHandler();
    final IdmAuthentication.CompletionHandler.CHALLENGE_TYPE challengeType = completionHandler.getChallengeType();
    List<String> availableButtons = getIntent().getStringArrayListExtra(BUTTONS_WEB_VIEW_PROP);

    final Button backBtn = _getBackButton();
    final Button forwardBtn = _getForwardButton();
    final Button reloadBtn = _getReloadButton();
    final Button cancelBtn = _getCancelButton(challengeType);

    _webViewClient = _createWebViewClient(challengeType, backBtn, forwardBtn, reloadBtn, cancelBtn, availableButtons);
    _broadcastReceiver = _createBroadcastReceiver();
    _localBroadcastManager = LocalBroadcastManager.getInstance(this);
    _localBroadcastManager.registerReceiver(_broadcastReceiver, new IntentFilter(FINISH_WEB_VIEW_INTENT));

    _proceed(completionHandler);
    Log.d(TAG, "Created webview activity and passed on to IDM SDK.");
  }

  @Override
  protected void onDestroy()
  {
    super.onDestroy();
    _localBroadcastManager.unregisterReceiver(_broadcastReceiver);
    Log.d(TAG,"Destroyed webview activity.");
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
            Log.d(TAG, "Finishing the activity.");
            _webView.destroy();
            finish();
          }
        }
    };
  }

  private WebViewClient _createWebViewClient(final IdmAuthentication.CompletionHandler.CHALLENGE_TYPE challengeType,
                                             final Button backBtn,
                                             final Button forwardBtn,
                                             final Button reloadBtn,
                                             final Button cancelBtn,
                                             final List<String> availableButtons) {
    return new WebViewClient()
    {
      @Override
      public void onPageFinished(WebView view, String url)
      {
        Log.d(TAG, "WebView is loaded now. Enabling buttons if its login flow...");
        if (challengeType == IdmAuthentication.CompletionHandler.CHALLENGE_TYPE.LOGIN) {
          if(availableButtons.contains(_NO_BTN_FLAG)) {
            LinearLayout buttonLayout = (LinearLayout) findViewById(_R.getIdentifier(_BTN_LAYOUT));
            buttonLayout.setVisibility(View.GONE);
            return;
          }

          boolean hasAllButtons = availableButtons.contains(_ALL_BTN_FLAG);
          if(hasAllButtons || availableButtons.contains(_BACK_BTN_FLAG)) {
            backBtn.setVisibility(View.VISIBLE);
            backBtn.setEnabled(true);
          }
          if(hasAllButtons || availableButtons.contains(_FORWARD_BTN_FLAG)) {
            forwardBtn.setVisibility(View.VISIBLE);
            forwardBtn.setEnabled(true);
          }
          if(hasAllButtons || availableButtons.contains(_RELOAD_BTN_FLAG)) {
            reloadBtn.setVisibility(View.VISIBLE);
            reloadBtn.setEnabled(true);
          }
          if(hasAllButtons || availableButtons.contains(_CANCEL_BTN_FLAG)) {
            cancelBtn.setVisibility(View.VISIBLE);
            cancelBtn.setEnabled(true);
          }
        }
      }
    };
  }

  private Button _getCancelButton(IdmAuthentication.CompletionHandler.CHALLENGE_TYPE challengeType)
  {
    Button cancelBtn = (Button) findViewById(_R.getIdentifier(_CANCEL_BTN_ID));
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
            _localBroadcastManager.sendBroadcast(new Intent(CANCEL_WEB_VIEW_INTENT));
          }
        });
      }
    });
    cancelBtn.setEnabled(false);
    cancelBtn.setVisibility(View.GONE);
    return cancelBtn;
  }

  private Button _getReloadButton()
  {
    Button reloadBtn = (Button) findViewById(_R.getIdentifier(_RELOAD_BTN_ID));
    reloadBtn.setOnClickListener(new View.OnClickListener()
    {
      @Override
      public void onClick(View v)
      {
        _webView.reload();
      }
    });
    reloadBtn.setEnabled(false);
    reloadBtn.setVisibility(View.GONE);
    return reloadBtn;
  }

  private Button _getForwardButton()
  {
    Button forwardBtn = (Button) findViewById(_R.getIdentifier(_FORWARD_BTN_ID));
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
    forwardBtn.setEnabled(false);
    forwardBtn.setVisibility(View.GONE);
    return forwardBtn;
  }

  private Button _getBackButton()
  {
    Button backBtn = (Button) findViewById(_R.getIdentifier(_BACK_BTN_ID));
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
    backBtn.setEnabled(false);
    backBtn.setVisibility(View.GONE);
    return backBtn;
  }

  private WebView _webView;
  private WebViewClient _webViewClient;
  private BroadcastReceiver _broadcastReceiver;
  private LocalBroadcastManager _localBroadcastManager;

  private static final String TAG = WebViewActivity.class.getSimpleName();
  private static final ResourceHelper _R = ResourceHelper.INSTANCE;
  private static final String _ACTIVITY_WEB_VIEW = "activity_web_view";
  private static final String _IDM_WEB_VIEW = "idmWebView";
  private static final String _BTN_LAYOUT = "button_layout";
  private static final String _CANCEL_BTN_ID = "webViewCancelBtn";
  private static final String _RELOAD_BTN_ID = "webViewReloadBtn";
  private static final String _FORWARD_BTN_ID = "webViewFwdBtn";
  private static final String _BACK_BTN_ID = "webViewBackBtn";
  private static final String _CANCEL_BTN_FLAG = "CANCEL";
  private static final String _RELOAD_BTN_FLAG = "REFRESH";
  private static final String _FORWARD_BTN_FLAG = "FORWARD";
  private static final String _BACK_BTN_FLAG = "BACK";
  private static final String _ALL_BTN_FLAG = "ALL";
  private static final String _NO_BTN_FLAG = "NONE";
}
