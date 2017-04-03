/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.maf.security.idm;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

import oracle.idm.mobile.logging.OMLog;
import org.apache.cordova.CallbackContext;
import org.json.JSONObject;

import android.app.Activity;

/**
 * This class is a factory which manages different authentication flows.
 * The plugin supports multiple authentication flows in parallel. This factory inits the authentication flow and looks up
 * the flow based on UUID when requested.
 */
public class IdmAuthenticationFactory
{
  /**
   * Retrieve auth object based on UUID.
   * @param uuid identifier for the auth.
   * @return auth object if found, null otherwise.
   */
  public static IdmAuthentication get(String uuid)
  {
    return _AUTH_CACHE.get(uuid);
  }

  /**
   * Create a new auth for the parameters passed.
   * @param context
   * @param callback
   * @param props authentication properties to be used to create IDM OMMSS instance.
   * @return auth object
   */
  public static String create(Activity context, CallbackContext callback, JSONObject props)
  {
    OMLog.debug(TAG, "Creating new Authentication flow.");
    IdmAuthentication idmAuthentication = new IdmAuthentication(context, props);
    if (idmAuthentication.setup(callback))
    {
      String key = UUID.randomUUID().toString();
      _AUTH_CACHE.put(key, idmAuthentication);
      return key;
    }

    OMLog.debug(TAG, "Failed to creating new Authentication flow.");
    return null;
  }

  /**
   * Checks if the auth object for the uuid exists.
   * @param uuid identifier for the auth.
   * @return auth object.
   */
  public static boolean isValidAuthFlowKey(String uuid)
  {
    return _AUTH_CACHE.containsKey(uuid);
  }

  private static final Map<String, IdmAuthentication> _AUTH_CACHE = new HashMap<String, IdmAuthentication>();
  private static final String TAG = IdmAuthenticationFactory.class.getSimpleName();
}
