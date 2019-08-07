/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.idm.auth.plugin;

import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.concurrent.CountDownLatch;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Looper;
import android.support.customtabs.CustomTabsIntent;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Log;
import android.widget.Toast;

import oracle.idm.auth.plugin.util.PluginErrorCodes;
import oracle.idm.auth.plugin.customtabs.CustomTabActivityHelper;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OMAuthenticationChallenge;
import oracle.idm.mobile.auth.OMAuthenticationChallengeType;
import oracle.idm.mobile.auth.OMAuthenticationCompletionHandler;
import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.auth.OMAuthenticationContext.TimeoutType;
import oracle.idm.mobile.auth.OMToken;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.callback.OMAuthenticationContextCallback;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import android.app.Activity;
import android.content.Intent;
import android.os.Handler;
import android.util.Base64;

/**
 * This class interfaces with Android IDM SDK and performs authentication operations such as login, logout etc.
 */
public class IdmAuthentication implements OMMobileSecurityServiceCallback, OMAuthenticationContextCallback
{
  /**
   * Constructor - for each authentication
   * @param mainActivity
   * @param props
   */
  IdmAuthentication(Activity mainActivity, JSONObject props) 
  {
    _mainActivity = mainActivity;
    _props = _convertToAuthConfigProperties(props);
    _authType = (OMMobileSecurityService.AuthServerType) _props.get(OMMobileSecurityService.OM_PROP_AUTHSERVER_TYPE);
    _handler = new Handler(Looper.getMainLooper());
    _isWebViewChallenge = false;
    _externalBrowserChallengeResponseExpected = false;
    _localBroadcastManager = LocalBroadcastManager.getInstance(_mainActivity);
    _webViewButtonsArray = getWebViewButtonsArray(props.optJSONArray(PROP_ENABLE_WEB_VIEW_BUTTONS));
    _broadcastReceiver = new BroadcastReceiver() {
      @Override
      public void onReceive(Context context, Intent intent) {
        if (WebViewActivity.CANCEL_WEB_VIEW_INTENT.equals(intent.getAction())) {
          _cancelLoginFromWebView();
        }
      }
    };
  }

  /**
   * Set up the IDM OMMSS instance.
   * @param callback for communicating success or error.
   * @return
   */
  public boolean setup(final CallbackContext callback)
  {
    Log.d(TAG, "Setting up OMMSS instance with: " + _props);
    try
    {
      _ommss = new OMMobileSecurityService(_mainActivity, _props, this);
      _ommss.setup();
      _setupLatch.await();

      if (_setupException != null)
      {
        throw _setupException;
      }
    }
    catch (OMMobileSecurityException securityEx)
    {
      Log.e(TAG, "Error while setting up OMMSS instance.");
      IdmAuthenticationPlugin.invokeCallbackError(callback, securityEx);
      return false;
    } catch (InterruptedException e) {
      Log.e(TAG, "Error while setting up OMMSS instance.");
      IdmAuthenticationPlugin.invokeCallbackError(callback, PluginErrorCodes.SETUP_ERROR);
      return false;
    }
    return true;
  }

  /**
   * Initate login. The challenge callback from IDM will take the login process forward.
   * @param loginCallback executed when IDM invokes onAuthenticationChallenge.
   */
  public void startLogin(final CallbackContext loginCallback)
  {
    Log.d(TAG, "Start login process.");
    _loginCallback = loginCallback;
    _mainActivity.runOnUiThread(() -> {
      try
      {
        _ommss.authenticate();
      }
      catch (OMMobileSecurityException securityEx)
      {
        Log.e(TAG, "Error while login: " + securityEx.getMessage());
        IdmAuthenticationPlugin.invokeCallbackError(loginCallback, securityEx);
      }
    });
  }

  public void cancelLogin(final CallbackContext loginCallback) {
    Log.d(TAG, "Cancel login.");
    _loginCallback = loginCallback;
    _mainActivity.runOnUiThread(() -> {
      _completionHandler.cancel();
    });
    Log.d(TAG, "Cancel login process completed.");
  }

  /**
   * Complete the login process.
   * @param challengeFieldsJson credentials collected from the user.
   * @param loginCallback executed when IDM invokes onAuthenticationCompleted.
   */
  public void finishLogin(final JSONObject challengeFieldsJson, final CallbackContext loginCallback)
  {
    Log.d(TAG, "Finish login process.");
    _loginCallback = loginCallback;
    final Map<String, Object> challengeFields = new HashMap<String, Object>();
    _mainActivity.runOnUiThread(() -> {
      Iterator<String> it = challengeFieldsJson.keys();
      while (it.hasNext())
      {
        String key = it.next();
        Object value = challengeFieldsJson.opt(key);
        if (value == JSONObject.NULL)
          value = null;

        challengeFields.put(key, value);
      }
      _completionHandler.proceed(challengeFields);
    });
  }

  /**
   * Initiate logout.
   * @param logoutCallback executed when IDM invokes onLogoutCompleted.
   * @param forget whether to forget the auth details.
   */
  public void logout(final CallbackContext logoutCallback, boolean forget)
  {
    Log.d(TAG, "Logout invoked with forget: " + forget);
    _logoutCallback = logoutCallback;
    _mainActivity.runOnUiThread(() -> _ommss.logout(forget));
  }

  /**
   * Finds out if user is currently authenticated or not.
   * @param props can contain the OAUTH scopes and refreshExpiredTokens indicator that is used while checking authenticated status of the user.
   * @param callbackContext executed with true|false depending on if the user is authenticated or not.
   */
  public void isAuthenticated(JSONObject props, CallbackContext callbackContext)
  {
    Log.d(TAG, "isAuthenticated invoked.");
    try
    {
      boolean isValid;
      OMAuthenticationContext context = _ommss.retrieveAuthenticationContext();

      if (context == null)
        isValid = false;
      else  if (_authType == OMMobileSecurityService.AuthServerType.OpenIDConnect10
          || _authType == OMMobileSecurityService.AuthServerType.OAuth20)
        isValid = checkIsValidForOauth(context, props);
      else
        isValid = context.isValid();

      Map<String, Object> authResponse = new HashMap<String, Object>();
      authResponse.put(_IS_AUTHENTICATED_KEY, isValid);
      callbackContext.success(new JSONObject(authResponse));
    }
    catch (OMMobileSecurityException securityEx)
    {
      Log.e(TAG, "Error while checking authentication status: " + securityEx.getMessage());
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, securityEx);
    }
  }

  private boolean checkIsValidForOauth(OMAuthenticationContext context, JSONObject props) {
    Set<String> scopeSet = Collections.EMPTY_SET;
    // There is no reason why we should not refresh the expired token if we can.
    boolean refreshExpiredTokens = true;

    if (props != null && props.length() > 0)
    {
      Iterator<String> keys = props.keys();
      while (keys.hasNext())
      {
        String key = keys.next();
        if (OMMobileSecurityService.OM_PROP_OAUTH_SCOPE.equals(key))
          scopeSet = _extractSet(props, key);
        else if (_REFRESH_EXPIRED_TOKENS.equals(key))
          refreshExpiredTokens = props.optBoolean(key);
      }
    }

    return context.isValid(scopeSet, refreshExpiredTokens);
  }

  /**
   * Invoked during init, if the user wants to register a callback for timeouts.
   * @param callbackContext executed when IDM invokes onTimeout.
   */
  public void addTimeoutCallback(CallbackContext callbackContext)
  {
    Log.d(TAG, "Adding timeout callback.");
    _timeoutCallback = callbackContext;
    _ommss.setAuthenticationContextCallback(this);
  }

  /**
   * Used to reset the idle timeout, provided there is time left to actually idle timeout.
   * This method is used in conjunction with the onTimeout callback.
   * @param callbackContext communicates error or success.
   */
  public void resetIdleTimeout(final CallbackContext callbackContext)
  {
    Log.d(TAG, "Resetting idle timeout.");
    _mainActivity.runOnUiThread(() -> {
      try
      {
        OMAuthenticationContext authContext = _ommss.retrieveAuthenticationContext();
        boolean resetSuccess = authContext.resetTimer();
        if (resetSuccess)
        {
          callbackContext.success();
        }
        else
        {
          //
          // There is no error code for this scenario in the wiki.
          //
          Log.d(TAG, "Resetting idle timeout failed.");
          IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.IDLE_TIMEOUT_RESET_FAILED);
        }
      }
      catch (OMMobileSecurityException securityEx)
      {
        Log.e(TAG, "Error while resetting idle timeout: " + securityEx.getMessage());
        IdmAuthenticationPlugin.invokeCallbackError(callbackContext, securityEx);
      }
    });
  }

  /**
   * Retrieves the headers, including custom headers, authorization headers required to make an XHR request at the JS layer.
   * @param callbackContext communicates the headers or error.
   * @param fedAuthSecuredUrl URL for which cookies and headers are requested. To be passed only for federated auth cases.
   */
  public void getHeaders(final CallbackContext callbackContext, String fedAuthSecuredUrl, Set<String> scopes)
  {
    Log.d(TAG, "Getting headers.");
    try
    {
      OMAuthenticationContext context = _ommss.retrieveAuthenticationContext();

      if (context == null) {
        IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.NO_AUTH_CONTEXT);
        return;
      }

      Map<String, Object> headers = new HashMap<String, Object>();

      switch(_authType)
      {
        case HTTPBasicAuth:
          headers = _fetchBasicAuthHeaders(context);
          break;
        case OAuth20:
        case OpenIDConnect10:
          headers = _fetchOauthHeaders(context, scopes);
          break;
        case FederatedAuth:
          if (isSamlFlow())
          {
            headers.putAll(_fetchOauthHeaders(context, scopes));
          }
          if (fedAuthSecuredUrl != null)
          {
            headers.putAll(context.getRequestParams(fedAuthSecuredUrl, false));
          }
          break;
      }

      headers.putAll(context.getCustomHeaders());
      callbackContext.success(new JSONObject(headers));
    }
    catch (OMMobileSecurityException securityEx)
    {
      Log.e(TAG, "Error while getting headers: " + securityEx.getMessage());
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, securityEx);
    }
  }

  /**
   * Handles external browser challenge input and passes it on to IDM SDK.
   * @param incomingUri
   */
  public void submitExternalBrowserChallengeResponse(Uri incomingUri) {
    if (_externalBrowserChallengeResponseExpected)
    {
      Map<String, Object> fields = new HashMap<String, Object>();
      fields.put(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY, incomingUri);
      _completionHandler.proceed(fields);
      _externalBrowserChallengeResponseExpected = false;
    } else
    {
      Log.i(TAG, "Not expecting a external browser challenge response, ignoring.");
    }
  }

  @Override
  public void onAuthenticationChallenge(OMMobileSecurityService ommss, OMAuthenticationChallenge challenge,
                                        final OMAuthenticationCompletionHandler completionHandler)
  {
    Log.d(TAG, "onAuthenticationChallenge invoked.");
    Map<String, Object> fields = challenge.getChallengeFields();

    Object o = fields.get(OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION);
    String errorCode = null;

    //
    // Remove any exception from the fields map returned to JS layer.
    //
    fields.remove(OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION);
    if (o != null && o instanceof OMMobileSecurityException)
    {
      OMMobileSecurityException securityEx = (OMMobileSecurityException) o;
      Log.w(TAG, "Exception returned in Challenge callback.", securityEx);
      errorCode = securityEx.getErrorCode();

      //
      // If server is not reachable, there is a network issue. Fail the login.
      //
      if (OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER.getErrorCode().equals(errorCode))
      {
        IdmAuthenticationPlugin.invokeCallbackError(_loginCallback, securityEx);
        return;
      }
    }

    _completionHandler = new CompletionHandler()
    {
      @Override
      public void proceed(Map<String, Object> map)
      {
        completionHandler.proceed(map);
      }

      @Override
      public void cancel()
      {
        completionHandler.cancel();
      }

      @Override
      public CHALLENGE_TYPE getChallengeType()
      {
        return CHALLENGE_TYPE.LOGIN;
      }
    };

    _challengeType = challenge.getChallengeType();

    switch (_challengeType)
    {
      case USERNAME_PWD_REQUIRED:
        Log.d(TAG, "Handling username password challenge.");
        Map<String, Object> fieldsMap = new HashMap<String, Object>();
        fieldsMap.put("challengeFields", fields);

        //
        // Populate error code in the fields so that UI can know what went wrong.
        //
        if (errorCode != null) {
          fields.put(_CHALLENGE_ERROR, IdmAuthenticationPlugin.errorToMap(errorCode));
        }

        _loginCallback.success(new JSONObject(fieldsMap));
        break;
      case EMBEDDED_WEBVIEW_REQUIRED:
        Log.d(TAG, "Handling embedded webview challenge.");
        _startWebView();
        break;
      case EXTERNAL_BROWSER_INVOCATION_REQUIRED:
        handleExternalBrowserChallenge(fields);
        break;
      case INVALID_REDIRECT_ENCOUNTERED:
        // The google way of redirecting to app via http://localhost
        // does not result in a challenge in Android. The challenge in Android
        // happens only when there is a POST request which moves from secured to non secured.
        _finishWebView();
        IdmAuthenticationPlugin.invokeCallbackError(_loginCallback, PluginErrorCodes.INVALID_REDIRECT_CHALLENGE);
        break;
      case UNTRUSTED_SERVER_CERTIFICATE:
        _finishWebView();
        IdmAuthenticationPlugin.invokeCallbackError(_loginCallback, PluginErrorCodes.UNTRUSTED_CHALLENGE);
        break;
      default:
        Log.w(TAG, "Unhandled challenge type encountered: " + _challengeType);
        IdmAuthenticationPlugin.invokeCallbackError(_loginCallback, PluginErrorCodes.UNSUPPORTED_CHALLENGE);
        break;
    }
  }

  @Override
  public void onLogoutChallenge(OMMobileSecurityService ommss, OMAuthenticationChallenge challenge,
                                final OMLogoutCompletionHandler completionHandler)
  {
    Log.d(TAG, "onLogoutChallenge invoked.");
    Map<String, Object> fields = challenge.getChallengeFields();
    _completionHandler = new CompletionHandler()
    {
      @Override
      public void proceed(Map<String, Object> map)
      {
        completionHandler.proceed(map);
      }

      @Override
      public void cancel()
      {
        completionHandler.cancel();
      }

      @Override
      public CHALLENGE_TYPE getChallengeType()
      {
        return CHALLENGE_TYPE.LOGOUT;
      }
    };
    if (challenge.getChallengeType() == OMAuthenticationChallengeType.EMBEDDED_WEBVIEW_REQUIRED)
    {
      //
      // Provide webview for logout via activity.
      //
      Log.d(TAG, "Handling embedded webview challenge");
      _startWebView();
    }
    else if (challenge.getChallengeType() == OMAuthenticationChallengeType.EXTERNAL_BROWSER_INVOCATION_REQUIRED)
    {
      handleExternalBrowserChallenge(fields);
    }
  }

  private void handleExternalBrowserChallenge(Map<String, Object> fields) {
    bindChromeTabs();
    Uri externalBrowserURL = Uri.parse((String) fields.get(OMSecurityConstants.Challenge.EXTERNAL_BROWSER_LOAD_URL));
    _customCustomTabActivityHelper.mayLaunchUrl(externalBrowserURL, null, null);
    CustomTabsIntent.Builder intentBuilder = new CustomTabsIntent.Builder(_customCustomTabActivityHelper.getSession());
    intentBuilder.setShowTitle(true);
    intentBuilder.enableUrlBarHiding();
    CustomTabActivityHelper.openCustomTab(_mainActivity, intentBuilder.build(), externalBrowserURL, new ExternalBrowserFallback());
  }

  private class ExternalBrowserFallback implements CustomTabActivityHelper.CustomTabFallback {
    @Override
    public void openUri(Activity activity, Uri uri) {
      Intent intent = new Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
      if (intent.resolveActivity(_mainActivity.getPackageManager()) != null)
      {
        _mainActivity.startActivity(intent);
        _externalBrowserChallengeResponseExpected = true;
      }
      else
      {
        Log.e(TAG, "Error while handling external browser challenge. Cannot launch external browser. Cancelling login.");
        IdmAuthenticationPlugin.invokeCallbackError(_loginCallback, PluginErrorCodes.EXTERNAL_BROWSER_LAUNCH_FAILED);
        _completionHandler.cancel();
      }
    }
  }

  @Override
  public void onSetupCompleted(OMMobileSecurityService ommss, OMMobileSecurityConfiguration config,
                               OMMobileSecurityException securityEx)
  {
    Log.d(TAG, "Setup completed.");
    _setupException = securityEx;
    _setupLatch.countDown();
    Log.d(TAG, "Exit Setup completed..");
  }

  @Override
  public void onAuthenticationCompleted(OMMobileSecurityService ommss, OMAuthenticationContext context,
                                        OMMobileSecurityException securityEx)
  {
    Log.d(TAG, "onAuthenticationCompleted invoked.");
    try
    {
      //
      // After login completed, dismiss the webview activity. Do this before even handling exception
      // during login, because the purpose of the activity is served either ways.
      //
      _finishWebView();
      unbindChromeTabs();

      if (securityEx != null)
      {
        Log.e(TAG, "Error in authentication completed: " + securityEx.getMessage());
        IdmAuthenticationPlugin.invokeCallbackError(_loginCallback, securityEx);
        return;
      }

      _loginCallback.success();
    }
    finally
    {
      _loginCallback = null;
    }
  }

  @Override
  public void onLogoutCompleted(OMMobileSecurityService ommss, OMMobileSecurityException securityEx)
  {
    Log.d(TAG, "onLogoutCompleted invoked");
    try
    {
      _finishWebView();
      unbindChromeTabs();

      if (securityEx != null)
      {
        Log.e(TAG, "Error in logout completed: " + securityEx.getMessage());
        IdmAuthenticationPlugin.invokeCallbackError(_logoutCallback, securityEx);
        return;
      }

      _logoutCallback.success();
    }
    finally
    {
      _logoutCallback = null;
    }
  }

  @Override
  public Handler getHandler()
  {
    return _handler;
  }

  @Override
  public void onTimeout(TimeoutType timeoutType, long timeLeftToTimeout)
  {
    Log.d(TAG, "onTimeout invoked");
    Map<String, String> resp = new HashMap<String, String>();
    resp.put("TimeoutType", timeoutType.toString());
    resp.put("TimeLeftToTimeout", String.valueOf(timeLeftToTimeout));
    PluginResult result = new PluginResult(PluginResult.Status.OK, new JSONObject(resp));
    result.setKeepCallback(true);
    _timeoutCallback.sendPluginResult(result);
  }

  /**
   * Encapsulate the proceed functionality in {@link OMAuthenticationCompletionHandler} and {@link OMLogoutCompletionHandler}
   */
  interface CompletionHandler
  {
    enum CHALLENGE_TYPE { LOGIN, LOGOUT };
    void proceed(Map<String, Object> map);
    void cancel();
    CHALLENGE_TYPE getChallengeType();
  }

  /**
   * The completion handler which can be either for login or logout.
   * @return
   */
  static CompletionHandler getCompletionHandler()
  {
    return _completionHandler;
  }

  /**
   * Utility method to launch the webview activity for authentication flows for which IDM requires embedded webview.
   */
  private void _startWebView()
  {
    Log.d(TAG, "Launching webview activity");
    _mainActivity.runOnUiThread(() -> {
      _localBroadcastManager.registerReceiver(_broadcastReceiver, new IntentFilter(WebViewActivity.CANCEL_WEB_VIEW_INTENT));
      Intent intent = new Intent(_mainActivity, WebViewActivity.class);
      intent.putStringArrayListExtra(WebViewActivity.BUTTONS_WEB_VIEW_PROP, _webViewButtonsArray);
      _mainActivity.startActivity(intent);
      _isWebViewChallenge = true;
    });
  }

  /**
   * Utility method to hide the webview activity after successful authentication or logout.
   */
  private void _finishWebView() {
    if (!_isWebViewChallenge) {
      return;
    }

    Log.d(TAG, "Hide webview after successful authentication or logout.");
    _mainActivity.runOnUiThread(() -> {
      _localBroadcastManager.sendBroadcast(new Intent(WebViewActivity.FINISH_WEB_VIEW_INTENT));
      _localBroadcastManager.unregisterReceiver(_broadcastReceiver);
      _isWebViewChallenge = false;
    });
  }

  /**
   * Handle user cancelled login from webView.
   */
  private void _cancelLoginFromWebView() {
    Log.d(TAG, "Cancel webview login.");
    _mainActivity.runOnUiThread(() -> {
      if (_completionHandler.getChallengeType() == CompletionHandler.CHALLENGE_TYPE.LOGIN)
      {
        _ommss.cancel();
      }
      Toast.makeText(_mainActivity.getApplicationContext(), "Cancel WebView Login", Toast.LENGTH_SHORT).show();
      _finishWebView();
    });
  }

  /**
   * Converts the authentication properties passed as JSON to a Map.
   * @param authPropsJson
   * @return
   */
  private Map<String, Object> _convertToAuthConfigProperties(JSONObject authPropsJson)
  {
    Log.d(TAG, "Converting JSON to auth map.");
    Map<String, Object> authProps = new HashMap<String, Object>();
    Iterator<String> keys = authPropsJson.keys();

    while (keys.hasNext())
    {
      String key = keys.next();
      //
      // Special handling needed for auth type enum as it is needed in plugin code.
      // Remaining enums will be auto converted by IDM SDK.
      //
      if (OMMobileSecurityService.OM_PROP_AUTHSERVER_TYPE.equals(key))
      {
        authProps.put(key, OMMobileSecurityService.AuthServerType.valueOfAuthServerType(authPropsJson.optString(key)));
        continue;
      }

      //
      // Special handling for collections.
      //
      if (OMMobileSecurityService.OM_PROP_OAUTH_SCOPE.equals(key))
      {
        Set<String> scopeSet = _extractSet(authPropsJson, key);
        if (scopeSet.size() > 0)
        {
          authProps.put(key, scopeSet);
        }
        continue;
      }

      if (OMMobileSecurityService.OM_PROP_CUSTOM_AUTH_HEADERS.equals(key)
          || OMMobileSecurityService.OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT.equals(key))
      {
        JSONObject customAuthPropsJson = authPropsJson.optJSONObject(key);

        if (customAuthPropsJson != null)
        {
          Iterator<String> customPropsKeys = customAuthPropsJson.keys();
          Map<String, String> customHeaders = new HashMap<String, String>();

          while (customPropsKeys.hasNext())
          {
            String customPropsKey = customPropsKeys.next();
            customHeaders.put(customPropsKey, customAuthPropsJson.optString(customPropsKey));
          }

          authProps.put(key, customHeaders);
        }
        continue;
      }

      authProps.put(key, authPropsJson.opt(key));
    }

    return authProps;
  }

  /**
   * Utility method to convert JSONArray to Set<String>
   * @param authPropsJson authentication properties JSON.
   * @param key value for which represents the JSONArray.
   * @return
   */
  private Set<String> _extractSet(JSONObject authPropsJson, String key)
  {
    Set<String> stringSet = new HashSet<String>();
    JSONArray scopes = authPropsJson.optJSONArray(key);

    if (scopes != null)
    {
      for (int i = 0, len = scopes.length(); i < len; i++)
      {
        String scope = scopes.optString(i);
        if (scope != null)
        {
          stringSet.add(scope);
        }
      }
    }

    return stringSet;
  }

  /**
   * Collects tokens for the scopes passed, and retunrs the first one in the form of a Bearer token
   * @param context
   * @param scopes
   * @return Map containing "Authorization" header with value set to Bearer token.
   */
  private Map<String, Object> _fetchOauthHeaders(OMAuthenticationContext context, Set<String> scopes)
  {
    Map<String, Object> headers = new HashMap<String, Object>();
    Log.d(TAG, "Collect headers for OAUTH from auth context or scope set " + scopes);

    //
    // All tokens returned are valid for the provided scopes, return first one.
    //
    List<OMToken> tokens = context.getTokens(scopes);
    if (tokens.size() > 0)
    {
      addAuthorizationHeader(headers, _BEARER, tokens.get(0).getValue());
    }
    return headers;
  }

  /**
   * Obtains username and password saved by IDM, creates basic auth headers and returns in a Map.
   * @param context
   * @return Map containing "Authorization" header with value set to Base64 encoded username and password.
   */
  private Map<String, Object> _fetchBasicAuthHeaders(OMAuthenticationContext context)
  {
    Log.d(TAG, "Collect auth header from auth context for HTTP Basic.");
    Map<String, Object> headers = new HashMap<String, Object>();
    Map<String, Object> contextHeaders = context.getCredentialInformation(new String[]{OMAuthenticationContext.CREDENTIALS});
    String userName = (String) contextHeaders.get("javax.xml.ws.security.auth.username");
    String password = (String) contextHeaders.get("javax.xml.ws.security.auth.password");

    if (userName != null && password != null)
    {
      String authValue = new StringBuilder(userName).append(':').append(password).toString();
      try
      {
        addAuthorizationHeader(headers, _BASIC,
                               Base64.encodeToString(authValue.trim().getBytes("UTF-8"),
                                                     Base64.NO_WRAP));
      }
      catch (UnsupportedEncodingException e)
      {
        // This will never happen because the string itself is created locally.
        // Still for completeness, add a log.
        Log.e(TAG, "UnsupportedEncodingException while creating Authorization header.");
      }
    }

    return headers;
  }

  /**
   * Adds authorization header to the map.
   * @param headers
   * @param tokenType
   * @param token
   */
  private void addAuthorizationHeader(Map<String, Object> headers, String tokenType, String token)
  {
    headers.put(_AUTHORIZATION, String.format(_TOKEN_FORMAT, tokenType, token));
  }


  /**
   * @return true When OM_PROP_PARSE_TOKEN_RELAY_RESPONSE set to true, false otherwise.
   */
  private boolean isSamlFlow()
  {
    Object tokenRelayResp = _props.get(OMMobileSecurityService.OM_PROP_PARSE_TOKEN_RELAY_RESPONSE);
    return tokenRelayResp != null && (Boolean) tokenRelayResp;
  }

  private void bindChromeTabs() {
    if (_customCustomTabActivityHelper == null)
      _customCustomTabActivityHelper = new CustomTabActivityHelper();

    _customCustomTabActivityHelper.bindCustomTabsService(_mainActivity);
    _customCustomTabActivityHelper.setConnectionCallback(new CustomTabActivityHelper.ConnectionCallback() {
      @Override
      public void onCustomTabsConnected() {
        _externalBrowserChallengeResponseExpected = true;
      }

      @Override
      public void onCustomTabsDisconnected() {}
    });
  }

  private void unbindChromeTabs() {
    if (_customCustomTabActivityHelper == null)
      return;

    _customCustomTabActivityHelper.unbindCustomTabsService(_mainActivity);
  }

  private static final String TAG = IdmAuthentication.class.getSimpleName();
  private static final String _AUTHORIZATION = "Authorization";
  private static final String _TOKEN_FORMAT = "%s %s";
  private static final String _BEARER = "Bearer";
  private static final String _BASIC = "Basic";
  private static final String _CHALLENGE_ERROR = "error";
  private static final String _REFRESH_EXPIRED_TOKENS = "refreshExpiredTokens";
  private static final String _IS_AUTHENTICATED_KEY = "isAuthenticated";
  private static final String PROP_ENABLE_WEB_VIEW_BUTTONS = "EnableWebViewButtons";

  /**
   * Creates list of strings from JSON object used to identify buttons on web view.
   * @param buttonArray of buttons
   * @return list containing buttons to be displayed on web view.
   */
  private ArrayList<String> getWebViewButtonsArray(JSONArray buttonArray) {
    ArrayList<String> availableButtons = new ArrayList<String>();
    if (buttonArray == null || buttonArray.length() == 0) {
      return availableButtons;
    }

    for (int i = 0; i < buttonArray.length(); i++) {
      availableButtons.add(buttonArray.optString(i));
    }

    return availableButtons;
  }

  /**
   * Static because this is shared with the WebViewActivity. This cannot be sent to the activity via putExtra
   * because IDM's challenge handler is not serializable. If we find a better way to share object to
   * WebViewActivity, we should do that and get rid of static.
   */
  private static CompletionHandler _completionHandler;

  private final OMMobileSecurityService.AuthServerType _authType;
  private final Activity _mainActivity;
  private final Map<String, Object> _props;
  private final BroadcastReceiver _broadcastReceiver;
  private final LocalBroadcastManager _localBroadcastManager;
  private final ArrayList<String> _webViewButtonsArray;
  private CallbackContext _loginCallback;
  private CallbackContext _logoutCallback;
  private CallbackContext _timeoutCallback;
  private Handler _handler;
  private OMAuthenticationChallengeType _challengeType;
  private OMMobileSecurityService _ommss;
  private boolean _isWebViewChallenge;
  private CustomTabActivityHelper _customCustomTabActivityHelper;
  private boolean _externalBrowserChallengeResponseExpected;
  private CountDownLatch _setupLatch = new CountDownLatch(1);
  private OMMobileSecurityException _setupException;
}
