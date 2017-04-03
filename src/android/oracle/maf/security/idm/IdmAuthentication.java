/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.maf.security.idm;

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Looper;
import android.widget.Toast;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OMAuthenticationChallenge;
import oracle.idm.mobile.auth.OMAuthenticationChallengeType;
import oracle.idm.mobile.auth.OMAuthenticationCompletionHandler;
import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.auth.OMAuthenticationContext.TimeoutType;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.callback.OMAuthenticationContextCallback;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;

import oracle.idm.mobile.logging.OMLog;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;

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
  }

  /**
   * Set up the IDM OMMSS instance.
   * @param callback for communicating success or error.
   * @return
   */
  public boolean setup(final CallbackContext callback)
  {
    OMLog.debug(TAG, "Setting up OMMSS instance.");
    try
    {
      _ommss = new OMMobileSecurityService(_mainActivity, _props, this);
      _registerLoginCancelFromWebViewBroadcastReceiver();
    }
    catch (OMMobileSecurityException securityEx)
    {
      OMLog.error(TAG, "Error while setting up OMMSS instance.");
      callback.error(securityEx.getErrorCode());
      return false;
    }
    return true;
  }

  private void _registerLoginCancelFromWebViewBroadcastReceiver() {
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        _broadcastReceiver = new BroadcastReceiver() {
          @Override
          public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();

            if (action.equals(WebViewActivity.CANCEL_LOGIN_INTENT)) {
              _cancelLoginFromWebView();
            }
          }
        };

        _mainActivity.registerReceiver(_broadcastReceiver, new IntentFilter(WebViewActivity.CANCEL_LOGIN_INTENT));
      }
    });
  }

  /**
   * Initate login. The challenge callback from IDM will take the login process forward.
   * @param loginCallback executed when IDM invokes onAuthenticationChallenge.
   */
  public void startLogin(final CallbackContext loginCallback)
  {
    OMLog.debug(TAG, "Start login process.");
    _loginLogoutCallback = loginCallback;
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        try
        {
          _ommss.authenticate();
        }
        catch (OMMobileSecurityException securityEx)
        {
          OMLog.error(TAG, "Error while login: " + securityEx.getMessage());
          loginCallback.error(securityEx.getErrorCode());
        }
      }
    });
  }

  /**
   * Complete the login process.
   * @param challengeFieldsJson credentials collected from the user.
   * @param loginCallback executed when IDM invokes onAuthenticationCompleted.
   */
  public void finishLogin(final JSONObject challengeFieldsJson, final CallbackContext loginCallback)
  {
    OMLog.debug(TAG, "Finish login process.");
    _loginLogoutCallback = loginCallback;
    final Map<String, Object> challengeFields = new HashMap<String, Object>();
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        Iterator<String> it = challengeFieldsJson.keys();
        while (it.hasNext())
        {
          String key = it.next();
          challengeFields.put(key, challengeFieldsJson.opt(key));
        }
        _completionHandler.proceed(challengeFields);
      }
    });
  }

  /**
   * Initiate logout.
   * @param logoutCallback executed when IDM invokes onLogoutCompleted.
   */
  public void logout(final CallbackContext logoutCallback)
  {
    OMLog.debug(TAG, "Logout invoked.");
    _loginLogoutCallback = logoutCallback;
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        _ommss.logout(false);
      }
    });
  }

  /**
   * Finds out if user is currently authenticated or not.
   * @param props can contain the OAUTH scopes and refreshExpiredTokens indicator that is used while checking authenticated status of the user.
   * @param callbackContext executed with true|false depending on if the user is authenticated or not.
   */
  public void isAuthenticated(JSONObject props, CallbackContext callbackContext)
  {
    OMLog.debug(TAG, "isAuthenticated invoked.");
    try
    {
      Set<String> scopeSet = null;
      boolean refreshExpiredTokens = false;
      
      if (props != null && props.length() > 0)
      {
        Iterator<String> keys = props.keys();
        while (keys.hasNext())
        {
          String key = keys.next();
          if (OMMobileSecurityService.OM_PROP_OAUTH_SCOPE.equals(key))
          {
            scopeSet = _extractSet(props, key);
            continue;
          }
          
          if ("refreshExpiredTokens".equals(key))
          {
            refreshExpiredTokens = props.optBoolean(key);
          }
        }
      }
      OMAuthenticationContext context = _ommss.retrieveAuthenticationContext();
      boolean isValid = false;
      
      if (context != null)
      {
        if (scopeSet != null)
        {
          OMLog.debug(TAG, "Invoking isValid with scopeSet and refreshExpiredTokens options.");
          isValid = context.isValid(scopeSet, refreshExpiredTokens);
        }
        else
        {
          OMLog.debug(TAG, "Invoking isValid.");
          isValid = context.isValid();
        }
      }
        
      Map<String, Object> authResponse = new HashMap<String, Object>();
      authResponse.put("isAuthenticated", isValid);
      callbackContext.success(new JSONObject(authResponse));
    }
    catch (OMMobileSecurityException securityEx)
    {
      OMLog.error(TAG, "Error while checking authentication status: " + securityEx.getMessage());
      callbackContext.error(securityEx.getErrorCode());
    }
  }

  /**
   * Invoked during init, if the user wants to register a callback for timeouts.
   * @param callbackContext executed when IDM invokes onTimeout.
   */
  public void addTimeoutCallback(CallbackContext callbackContext)
  {
    OMLog.debug(TAG, "Adding timeout callback.");
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
    OMLog.debug(TAG, "Resetting idle timeout.");
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
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
            OMLog.debug(TAG, "Resetting idle timeout failed.");
            callbackContext.error(_IDLE_TIMEOUT_RESET_FAILED);
          }
        }
        catch (OMMobileSecurityException securityEx)
        {
          OMLog.error(TAG, "Error while resetting idle timeout: " + securityEx.getMessage());
          callbackContext.error(securityEx.getErrorCode());
        }
      }
    });
  }

  /**
   * Retrives the headers, including custom headers, authorization headers required to make an XHR request at the JS layer.
   * @param callbackContext communicates the headers or error.
   * @param fedAuthSecuredUrl URL for which cookies and headers are requested. To be passed only for federated auth cases.
   */
  public void getHeaders(final CallbackContext callbackContext, String fedAuthSecuredUrl)
  {
    OMLog.debug(TAG, "Getting headers.");
    try
    {
      Object tokenRelayResp = _props.get(OMMobileSecurityService.OM_PROP_PARSE_TOKEN_RELAY_RESPONSE);
      boolean isMcsSamlFlow = false;

      if (tokenRelayResp != null) {
        isMcsSamlFlow = OMMobileSecurityService.AuthServerType.FederatedAuth == _authType
            && (Boolean) tokenRelayResp;
      }

      boolean isSecuredUrlSpecifiedForNonFedFlow = OMMobileSecurityService.AuthServerType.FederatedAuth != _authType
          && fedAuthSecuredUrl != null;
      if (isSecuredUrlSpecifiedForNonFedFlow || isMcsSamlFlow)
      {
        OMLog.warn(TAG, "Federated auth secured URL passed for non federated auth case or fed auth MCS SAML case. The parameter will be ignored.");
        fedAuthSecuredUrl = null;
      }

      OMAuthenticationContext context = _ommss.retrieveAuthenticationContext();
      Map<String, Object> headers;
      if (fedAuthSecuredUrl == null)
      {
        headers = _collectHeaders(context, isMcsSamlFlow);
      }
      else
      {
        headers = context.getRequestParams(fedAuthSecuredUrl, true);
      }

      if (headers == null)
      {
        headers = Collections.emptyMap();
      }
      callbackContext.success(new JSONObject(headers));
    }
    catch (OMMobileSecurityException securityEx)
    {
      OMLog.error(TAG, "Error while getting headers: " + securityEx.getMessage());
      callbackContext.error(securityEx.getErrorCode());
    }
  }
  
  @Override
  public void onAuthenticationChallenge(OMMobileSecurityService ommss, OMAuthenticationChallenge challenge,
                                        final OMAuthenticationCompletionHandler completionHandler)
  {
    OMLog.debug(TAG, "onAuthenticationChallenge invoked.");
    Map<String, Object> fields = challenge.getChallengeFields();

    //
    // Handle no network cases.
    //
    Object o = fields.get(OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION);
    String errorCode = null;

    //
    // If there are any exceptions remove that.
    //
    fields.remove(OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION);
    if (o != null && o instanceof OMMobileSecurityException)
    {
      OMMobileSecurityException securityEx = (OMMobileSecurityException) o;
      ((OMMobileSecurityException) o).printStackTrace();
      errorCode = securityEx.getErrorCode();
      if (OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER.getErrorCode().equals(errorCode))
      {
        _loginLogoutCallback.error(securityEx.getErrorCode());
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
    };

    _challengeType = challenge.getChallengeType();

    switch (_challengeType)
    {
      case USERNAME_PWD_REQUIRED:
        OMLog.debug(TAG, "Handling username password challenge.");
        Map<String, Object> fieldsMap = new HashMap<String, Object>();
        fieldsMap.put("challengeFields", fields);

        //
        // Populate error code in the fields so that UI can know what went wrong.
        //
        if (errorCode != null) {
          fields.put("errorCode", errorCode);
        }

        _loginLogoutCallback.success(new JSONObject(fieldsMap));
        break;
      case EMBEDDED_WEBVIEW_REQUIRED:
        OMLog.debug(TAG, "Handling embedded webview challenge.");
        _startWebView();
        break;
      case INVALID_REDIRECT_ENCOUNTERED:
        // The google way of redirecting to app via http://localhost
        // does not result in a challenge in Android. The challenge in Android
        // happens only when there is a POST request which moves from secured to non secured.
        _loginLogoutCallback.error(_REDIRECT_CHALLENGE_ERROR);
        break;
      case UNTRUSTED_SERVER_CERTIFICATE:
        _loginLogoutCallback.error(_UNTRUSTED_CHALLENGE_ERROR);
        break;
      default:
        OMLog.warn(TAG, "Unhandled challenge type encountered: " + _challengeType);
        _loginLogoutCallback.error(_UNSUPPORTED_CHALLENGE_ERROR);
        break;
    }
  }

  @Override
  public void onLogoutChallenge(OMMobileSecurityService ommss, OMAuthenticationChallenge challenge,
                                final OMLogoutCompletionHandler completionHandler)
  {
    OMLog.debug(TAG, "onLogoutChallenge invoked.");
    if (challenge.getChallengeType() == OMAuthenticationChallengeType.EMBEDDED_WEBVIEW_REQUIRED)
    {
      //
      // Provide webview for logout via activity.
      //
      OMLog.debug(TAG, "Handling embedded webview challenge");
      _completionHandler = new CompletionHandler()
      {
        @Override
        public void proceed(Map<String, Object> map)
        {
          completionHandler.proceed(map);
        }
      };
      _startWebView();
    }
  }

  @Override
  public void onAuthenticationCompleted(OMMobileSecurityService ommss, OMAuthenticationContext context,
                                        OMMobileSecurityException securityEx)
  {
    OMLog.debug(TAG, "onAuthenticationCompleted invoked.");
    try
    {
      //
      // After login completed, dismiss the webview activity. Do this before even handling exception
      // during login, because the purpose of the activity is served either ways.
      //
      _finishWebView();

      if (securityEx != null)
      {
        OMLog.error(TAG, "Error in authentication completed: " + securityEx.getMessage());
        _loginLogoutCallback.error(securityEx.getErrorCode());
        return;
      }
      
      _loginLogoutCallback.success();
    } 
    finally
    {
      _loginLogoutCallback = null;
    }
  }

  @Override
  public void onLogoutCompleted(OMMobileSecurityService ommss, OMMobileSecurityException securityEx)
  {
    OMLog.debug(TAG, "onLogoutCompleted invoked");
    try
    {
      _finishWebView();

      if (securityEx != null)
      {
        OMLog.error(TAG, "Error in logout completed: " + securityEx.getMessage());
        _loginLogoutCallback.error(securityEx.getErrorCode());
        return;
      }
        
      _loginLogoutCallback.success();
    }
    finally
    {
      _loginLogoutCallback = null;
    }
  }

  @Override
  public void onSetupCompleted(OMMobileSecurityService ommss, OMMobileSecurityConfiguration config,
                               OMMobileSecurityException securityEx)
  {
    // no-op: plug-in implementation does not need this callback.
  }
  
  @Override
  public Handler getHandler()
  {
    return _handler;
  }
  
  @Override
  public void onTimeout(TimeoutType timeoutType, long timeLeftToTimeout)
  {
    OMLog.debug(TAG, "onTimeout invoked");
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
    void proceed(Map<String, Object> map);
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
    OMLog.debug(TAG, "Launching webview activity");
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        Intent intent = new Intent(_mainActivity, WebViewActivity.class);
        _mainActivity.startActivity(intent);
        _isWebViewChallenge = true;
      }
    });
  }

  /**
   * Utility method to hide the webview activity after successful authentication or logout.
   */
  private void _finishWebView() {
    if (!_isWebViewChallenge) {
      return;
    }

    OMLog.debug(TAG, "Hide webview after successful authentication or logout.");
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        _mainActivity.sendBroadcast(new Intent(WebViewActivity.FINISH_WEB_VIEW_INTENT));
        _isWebViewChallenge = false;
      }
    });
  }

  private void _cancelLoginFromWebView() {
    OMLog.debug(TAG, "Cancel webview login.");
    _mainActivity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        _ommss.cancel();
        Toast.makeText(_mainActivity.getApplicationContext(), "Cancel WebView Login", Toast.LENGTH_SHORT).show();
        _mainActivity.sendBroadcast(new Intent(WebViewActivity.FINISH_WEB_VIEW_INTENT));
        _mainActivity.unregisterReceiver(_broadcastReceiver);
        _isWebViewChallenge = false;
      }
    });
  }

  /**
   * Converts the authentication properties passed as JSON to a Map.
   * @param authPropsJson
   * @return
   */
  private Map<String, Object> _convertToAuthConfigProperties(JSONObject authPropsJson)
  {
    OMLog.debug(TAG, "Converting JSON to auth map.");
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
      
      if (OMMobileSecurityService.OM_PROP_CUSTOM_AUTH_HEADERS.equals(key))
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
          authProps.put(OMMobileSecurityService.OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT, customHeaders);
        }
        continue;
      }
      
      authProps.put(key, authPropsJson.opt(key));
    }
    
    return authProps;
  }

  /**
   * Utility method to collect all headers based on the type of authentication used.
   * @param context
   * @return
   */
  private Map<String, Object> _collectHeaders(OMAuthenticationContext context, boolean isMcsSamlFlow)
  {
    Map<String, Object> headers = new HashMap<String, Object>();
    if (OMMobileSecurityService.AuthServerType.HTTPBasicAuth == _authType)
    {
      OMLog.debug(TAG, "Collect headers from auth context for HTTP Basic.");
      Map<String, Object> contextHeaders = context.getCredentialInformation(new String[] { "credentials" });
      String userName = (String) contextHeaders.get("javax.xml.ws.security.auth.username");
      String password = (String) contextHeaders.get("javax.xml.ws.security.auth.password");
      Object nestedHeaders = contextHeaders.get("headers");
      if (nestedHeaders != null && nestedHeaders instanceof Map)
      {
        headers.putAll((Map) nestedHeaders);
      }

      if (userName != null && password != null)
      {
        String authValue = new StringBuilder(userName).append(':').append(password).toString();
        try
        {
          headers.put("Authorization", "Basic " + Base64.encodeToString(authValue.trim().getBytes("UTF-8"), Base64.NO_WRAP));
        } catch (UnsupportedEncodingException e) {
          // This will never happen because the string itself is created locally.
          // Still for completeness, add a log.
          OMLog.error(TAG, "UnsupportedEncodingException while creating Authorization header.");
        }
      }
    }
    else if (OMMobileSecurityService.AuthServerType.OAuth20 == _authType || isMcsSamlFlow)
    {
      OMLog.debug(TAG, "Collect headers from auth context.");
      Map<String, Object> contextHeaders = context.getCredentialInformation(new String[]{OMSecurityConstants.OAUTH_ACCESS_TOKEN});
      headers = flatten(contextHeaders);
    }

    if (headers.isEmpty())
    {
      return null;
    }

    return headers;
  }

  /**
   * This method flattens the header map obtained from IDM SDK.
   * @param source
   */
  private Map<String, Object> flatten(Map<String, Object> source)
  {
    Map<String, Object> target = new HashMap<String, Object>();
    Object nestedHeaders = source.get("headers");
    if (nestedHeaders != null && nestedHeaders instanceof Map)
    {
      source.remove("headers");
      target.putAll((Map) nestedHeaders);
    }
    for (String key : source.keySet())
    {
      target.put(key, source.get(key));
    }
    return target;
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

  private static final String TAG = IdmAuthentication.class.getSimpleName();
  private static final String _REDIRECT_CHALLENGE_ERROR = "P1001";
  private static final String _UNTRUSTED_CHALLENGE_ERROR = "P1002";
  private static final String _UNSUPPORTED_CHALLENGE_ERROR = "P1003";
  private static final String _IDLE_TIMEOUT_RESET_FAILED = "P1004";

  /**
   * Static because this is shared with the WebViewActivity. This cannot be sent to the activity via putExtra
   * because IDM's challenge handler is not serializable. If we find a better way to share object to
   * WebViewActivity, we should do that and get rid of static.
   */
  private static CompletionHandler _completionHandler;

  private final OMMobileSecurityService.AuthServerType _authType;
  private final Activity _mainActivity;
  private final Map<String, Object> _props;
  private CallbackContext _loginLogoutCallback;
  private CallbackContext _timeoutCallback;
  private Handler _handler;
  private OMAuthenticationChallengeType _challengeType;
  private OMMobileSecurityService _ommss;
  private BroadcastReceiver _broadcastReceiver;
  private boolean _isWebViewChallenge;
}
