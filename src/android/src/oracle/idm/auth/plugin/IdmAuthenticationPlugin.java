/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.idm.auth.plugin;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import android.content.Intent;
import android.net.Uri;
import android.util.Log;
import oracle.idm.auth.plugin.local.LocalAuthentication;
import oracle.idm.auth.plugin.util.PluginErrorCodes;
import oracle.idm.auth.plugin.util.ResourceHelper;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.logging.OMLog;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This class is the Cordova plugin implementation that acts as the entry point.
 * This handles all requests from JS layer and provides response via the callback.
 */
public class IdmAuthenticationPlugin extends CordovaPlugin
{

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    _localAuth = new LocalAuthentication(cordova.getActivity());
    ResourceHelper.INSTANCE.init(cordova.getActivity().getResources(), cordova.getActivity().getPackageName());
  }

  /**
   * Handles actions from JS layer.
   * @param action
   * @param args
   * @param callbackContext
   * @return
   * @throws JSONException
   */
  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext)
  {
    if ("setup".equals(action))
    {
      _handleSetup(args, callbackContext);
      return true;
    }
    else if ("startLogin".equals(action))
    {
      _handleStartLogin(args, callbackContext);
      return true;
    }
    else if ("finishLogin".equals(action))
    {
      _handleFinishLogin(args, callbackContext);
      return true;
    }
    else if ("cancelLogin".equals(action))
    {
      _handleCancelLogin(args, callbackContext);
      return true;
    }
    else if ("logout".equals(action))
    {
      _handleLogout(args, callbackContext);
      return true;
    }
    else if ("isAuthenticated".equals(action))
    {
      _handleIsAuthenticated(args, callbackContext);
      return true;
    }
    else if ("getHeaders".equals(action))
    {
      _handleGetHeaders(args, callbackContext);
      return true;
    }
    else if ("addTimeoutCallback".equals(action))
    {
      _handleAddTimeoutCallback(args, callbackContext);
      return true;
    }
    else if ("resetIdleTimeout".equals(action))
    {
      _handleResetIdleTimeout(args, callbackContext);
      return true;
    }
    else if ("enabledLocalAuthsPrimaryFirst".equals(action))
    {
      _localAuth.enabledLocalAuthsPrimaryFirst(args, callbackContext);
      return true;
    }
    else if ("authenticatePin".equals(action))
    {
      _localAuth.authenticatePin(args, callbackContext);
      return true;
    }
    else if ("authenticateBiometric".equals(action))
    {
      _localAuth.authenticateBiometric(args, callbackContext);
      return true;
    }
    else if ("enableLocalAuth".equals(action))
    {
      _localAuth.enable(args, callbackContext);
      return true;
    }
    else if ("disableLocalAuth".equals(action))
    {
      _localAuth.disable(args, callbackContext);
      return true;
    }
    else if ("changePin".equals(action))
    {
      _localAuth.changePin(args, callbackContext);
      return true;
    }
    else if ("getLocalAuthSupportInfo".equals(action))
    {
      _localAuth.getLocalAuthSupportInfo(args, callbackContext);
      return true;
    }
    else if ("setPreference".equals(action))
    {
      _localAuth.setPreference(args, callbackContext);
      return true;
    }
    else if ("getPreference".equals(action))
    {
      _localAuth.getPreference(args, callbackContext);
      return true;
    }

    invokeCallbackError(callbackContext, "Invalid action: " + action);
    return false;
  }

  /**
   * Handle external browser redirects.
   * @param intent
   */
  @Override
  public void onNewIntent(Intent intent)
  {
    Log.d(TAG, "onNewIntent triggered: " + intent);
    if (Intent.ACTION_VIEW.equals(intent.getAction()))
    {
      Log.d(TAG, "onNewIntent is action view.");
      final Uri receivedUri = intent.getData();
      Log.d(TAG, "onNewIntent URI is: " + receivedUri);
      if (receivedUri != null && _currentAuthFlow != null)
      {
        _currentAuthFlow.submitExternalBrowserChallengeResponse(receivedUri);
      }
    }

    super.onNewIntent(intent);
  }

  /**
   *
   * @param context
   * @param error
   */
  public static void invokeCallbackError(CallbackContext context, OMMobileSecurityException error) {
    invokeCallbackError(context, error.getErrorCode());
  }

  /**
   *
   * @param context
   * @param errorCode
   */
  public static void invokeCallbackError(CallbackContext context, String errorCode) {
    if (errorCode == null || errorCode.isEmpty()) {
      OMLog.warn(TAG, "Error code to be sent to callback was null or empty. Returning internal error code.");
      errorCode = PluginErrorCodes.INTERNAL_ERROR;
    }

    if (context == null) {
      OMLog.error(TAG, String.format("Cannot send error code '%s'. Callback context is null.", errorCode));
      return;
    }

    context.error(new JSONObject(errorToMap(errorCode)));
  }

  /**
   * Convert errorCode to an error map that can be passed on to javascript.
   * @param errorCode
   * @return
   */
  public static Map<String, String> errorToMap(String errorCode) {
    Map<String, String> errorResult = new HashMap<String, String>();
    errorResult.put(ERROR_CODE, errorCode);
    errorResult.put(ERROR_SOURCE, PLUGIN_ERROR_SOURCE);
    errorResult.put(TRANSLATED_ERROR_MSG, "");
    return errorResult;
  }

  /**
   * Handles setup call for a new auth.
   * @param args
   * @param callbackContext
   */
  private void _handleSetup(JSONArray args, CallbackContext callbackContext)
  {
    // Index check is done by the opt method automatically.
    JSONObject jsonObject = args.optJSONObject(0);
    if (jsonObject == null)
    {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.NULL_ARGS_FOR_INIT);
      return;
    }

    Map<String, Object> map =  new HashMap<String, Object>();
    String token = _factory.create(cordova.getActivity(), callbackContext, jsonObject);

    if (token == null)
    {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.SETUP_ERROR);
      return;
    }

    map.put(AUTH_FLOW_KEY, token);
    callbackContext.success(new JSONObject(map));
  }

  /**
   * Handles login initiation call.
   * @param args
   * @param callbackContext
   */
  private void _handleStartLogin(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }

    auth.startLogin(callbackContext);
  }

  /**
   * Handles finish login call.
   * @param args
   * @param callbackContext
   */
  private void _handleFinishLogin(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }

    JSONObject challengeFields = args.optJSONObject(1);

    if (challengeFields == null)
    {
      OMLog.warn(TAG, "No challenge fields passed.");
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.NULL_ARGS_FOR_CHALLENGE);
      return;
    }

    auth.finishLogin(challengeFields, callbackContext);
  }

  /**
   * Handles cancel login call.
   * @param args
   * @param callbackContext
   */
  private void _handleCancelLogin(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }

    auth.cancelLogin(callbackContext);
  }

  /**
   * Handles isAuthenticated call.
   * @param args
   * @param callbackContext
   */
  private void _handleIsAuthenticated(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }

    JSONObject props = args.optJSONObject(1);
    auth.isAuthenticated(props, callbackContext);
  }

  /**
   * Handles getHeaders call.
   * @param args
   * @param callbackContext
   */
  private void _handleGetHeaders(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }

    auth.getHeaders(callbackContext,
                    getStringFromJsonArray(args, 1),
                    getSetFromJsonArray(args, 2));
  }

  /**
   * Handles logout call.
   * @param args
   * @param callbackContext
   */
  private void _handleLogout(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }
    auth.logout(callbackContext, args.optBoolean(1));
  }

  /**
   * Handles addTimeoutCallback call.
   * @param args
   * @param callbackContext
   */
  private void _handleAddTimeoutCallback(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }
    auth.addTimeoutCallback(callbackContext);
  }

  /**
   * Handles resetIdleTimeout call.
   * @param args
   * @param callbackContext
   */
  private void _handleResetIdleTimeout(JSONArray args, CallbackContext callbackContext)
  {
    IdmAuthentication auth = _validateArgsAndGetAuth(args, callbackContext);
    if (auth == null)
    {
      return;
    }
    auth.resetIdleTimeout(callbackContext);
  }

  /**
   * Validates the arguments passed and obtains the auth object.
   * @param args
   * @param callbackContext communicates success or failure.
   * @return
   */
  private IdmAuthentication _validateArgsAndGetAuth(JSONArray args, CallbackContext callbackContext) {
    Log.d(TAG, "Validating arguments.");
    if (args == null || args.length() == 0)
    {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.NULL_ARGS);
      return null;
    }

    String authFlowKey = getStringFromJsonArray(args, 0);
    if (authFlowKey == null)
    {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.NULL_AUTH_FLOW_KEY);
      return null;
    }

    if (!_factory.isValidAuthFlowKey(authFlowKey))
    {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.INVALID_AUTH_FLOW_KEY);
      return null;
    }

    _currentAuthFlow = _factory.get(authFlowKey);

    if (_currentAuthFlow == null)
    {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.NO_AUTH_CONTEXT);
      return null;
    }

    return _currentAuthFlow;
  }

  /**
   * Extract string from the JSONArray.
   * @param args
   * @param index
   * @return null if string is empty or "null", string otherwise.
   */
  private String getStringFromJsonArray(JSONArray args, int index) {
    String result = args.optString(index);
    return (result.isEmpty() || "null".equals(result)) ? null : result;
  }

  /**
   * Extract Set from the JSONArray.
   * @param args
   * @param index
   * @return empty set if item at the specified index is null or empty.
   */
  private Set<String> getSetFromJsonArray(JSONArray args, int index) {
    Set<String> set = new HashSet<String>();
    JSONArray result = args.optJSONArray(index);

    try {
      if (result != null)
        for (int i = 0; i < result.length(); i++)
          set.add(result.getString(i));
    } catch (JSONException jEx) {
      Log.e(TAG, "Exception while parsing set from input.", jEx);
    }

    return set;
  }

  private IdmAuthentication _currentAuthFlow;
  private IdmAuthenticationFactory _factory = IdmAuthenticationFactory.INSTANCE;
  private LocalAuthentication _localAuth;

  // This should sync with idmAuthFlowPlugin.AuthFlowKey value in the Javascript API.
  private static final String AUTH_FLOW_KEY = "AuthFlowKey";
  private static final String PLUGIN_ERROR_SOURCE = "plugin";
  private static final String ERROR_CODE = "errorCode";
  private static final String ERROR_SOURCE = "errorSource";
  private static final String TRANSLATED_ERROR_MSG = "translatedErrorMessage";

  private static final String TAG = IdmAuthenticationPlugin.class.getSimpleName();
}
