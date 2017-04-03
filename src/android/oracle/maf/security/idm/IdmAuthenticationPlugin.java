/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.maf.security.idm;

import java.util.HashMap;
import java.util.Map;

import oracle.idm.mobile.logging.OMLog;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This class is the Cordova plugin implementation that acts as the entry point.
 * This handles all requests from JS layer and provides response via the callback.
 */
public class IdmAuthenticationPlugin extends CordovaPlugin
{
  /**
   * Called after plugin construction and fields have been initialized.
   */
  @Override
  protected void pluginInitialize()
  {
    _isSlf4jDependencyAvailable = isSlf4jDependencyLoaded();
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
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException
  {
    //
    // Android IDM SDK needs slf4j dependency to be provided at runtime. This is documented in the plugin documentation.
    // But if someone forgets to do this config, they should know what is going wrong.
    //
    if (!_isSlf4jDependencyAvailable)
    {
      callbackContext.error(_SLF4J_MISSING);
      return false;
    }

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
    
    callbackContext.error("Invalid action: " + action);
    return false;
  }

  private boolean isSlf4jDependencyLoaded()
  {
    try
    {
      Class.forName("org.slf4j.Logger");
    }
    catch (ClassNotFoundException e)
    {
      System.out.println("Required dependency 'org.slf4j' not found at runtime. All subsequent calls to use the plugin will fail." +
          " See plugin documentation for more details.");
      return false;
    }

    return true;
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
      callbackContext.error(_NULL_ARGS_FOR_INIT);
      return;
    }
    
    Map<String, Object> map =  new HashMap<String, Object>();
    String token = IdmAuthenticationFactory.create(cordova.getActivity(), callbackContext, jsonObject);
    
    if (token == null)
    {
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
      callbackContext.error(_NULL_ARGS_FOR_CHALLENGE);
      return;
    }
    
    auth.finishLogin(challengeFields, callbackContext);
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

    String fedAuthSecuredUrl = getStringFromJsonArray(args, 1);
    auth.getHeaders(callbackContext, fedAuthSecuredUrl);
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
    auth.logout(callbackContext);
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
    OMLog.debug(TAG, "Validating arguments.");
    if (args == null || args.length() == 0)
    {
      callbackContext.error(_NULL_ARGS);
      return null;
    }

    String authFlowKey = getStringFromJsonArray(args, 0);
    if (authFlowKey == null)
    {
      callbackContext.error(_NULL_AUTH_FLOW_KEY);
      return null;
    }

    if (!IdmAuthenticationFactory.isValidAuthFlowKey(authFlowKey))
    {
      callbackContext.error(_INVALID_AUTH_FLOW_KEY);
      return null;
    }

    _currentAuthFlow = IdmAuthenticationFactory.get(authFlowKey);
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

  private boolean _isSlf4jDependencyAvailable = false;
  private IdmAuthentication _currentAuthFlow;

  // This should sync with idmAuthFlowPlugin.AuthFlowKey value in the Javascript API.
  private static final String _NULL_ARGS_FOR_INIT = "P1005";
  private static final String _NULL_ARGS_FOR_CHALLENGE = "P1006";
  private static final String _NULL_ARGS = "P1007";
  private static final String _NULL_AUTH_FLOW_KEY = "P1008";
  private static final String _INVALID_AUTH_FLOW_KEY = "P1009";
  private static final String _SLF4J_MISSING = "P1011";
  private static final String AUTH_FLOW_KEY = "AuthFlowKey";
  private static final String TAG = IdmAuthenticationPlugin.class.getSimpleName();
}
