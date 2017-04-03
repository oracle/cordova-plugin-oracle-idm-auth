/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.maf.security.idm;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import android.content.res.Resources;
import android.view.View;
import android.widget.Button;
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
  public static final String CANCEL_LOGIN_INTENT = "cancelLoginFromWebView";



  @Override
  protected void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);
    Resources resources = getApplication().getResources();
    String packageName = getApplication().getPackageName();

    setContentView(resources.getIdentifier("activity_web_view", "layout", packageName));
    webView = (WebView) findViewById(resources.getIdentifier("idmWebView", "id", packageName));
    webView.getSettings().setJavaScriptEnabled(true);

    getActionBar().hide();

    final Button backBtn = (Button) findViewById(resources.getIdentifier("webViewBackBtn", "id", packageName));
    backBtn.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        if (webView.canGoBack()) {
          webView.goBack();
        }
      }
    });

    final Button forwardBtn = (Button) findViewById(resources.getIdentifier("webViewFwdBtn", "id", packageName));
    forwardBtn.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        if (webView.canGoForward()) {
          webView.goForward();
        }
      }
    });

    final Button reloadBtn = (Button) findViewById(resources.getIdentifier("webViewReloadBtn", "id", packageName));
    reloadBtn.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        webView.reload();
      }
    });

    final Button cancelBtn = (Button) findViewById(resources.getIdentifier("webViewCancelBtn", "id", packageName));
    cancelBtn.setOnClickListener(new View.OnClickListener() {
      @Override
      public void onClick(View v) {
        runOnUiThread(new Runnable() {
          @Override
          public void run() {
            sendBroadcast(new Intent(CANCEL_LOGIN_INTENT));
          }
        });
      }
    });

    webView.setWebViewClient( new WebViewClient() {
      @Override
      public void onPageFinished( WebView view, String url ) {
        super.onPageFinished(webView, url );
        backBtn.setEnabled(view.canGoBack());
        forwardBtn.setEnabled(view.canGoForward());
      }
    });

    _broadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent)
        {
          String action = intent.getAction();
          if (FINISH_WEB_VIEW_INTENT.equals(action)) {
            finish();
          }
        }
    };

    registerReceiver(_broadcastReceiver, new IntentFilter(FINISH_WEB_VIEW_INTENT));
    
    Map<String, Object> responseFields = new HashMap<String, Object>();
    responseFields.put(OMSecurityConstants.Challenge.WEBVIEW_KEY, webView);
    responseFields.put(OMSecurityConstants.Challenge.WEBVIEW_CLIENT_KEY, webViewClient);
    IdmAuthentication.getCompletionHandler().proceed(responseFields);
    _logger.fine("Created webview activity and passed on to IDM SDK.");
  }



  @Override
  protected void onDestroy()
  {
    super.onDestroy();
    unregisterReceiver(_broadcastReceiver);
    _logger.fine("Destroyed webview activity.");
  }

  private WebView webView;
  private WebViewClient webViewClient;
  private BroadcastReceiver _broadcastReceiver;
  private static final Logger _logger = Logger.getLogger("WebViewActivity");
}
