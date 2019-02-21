/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
package oracle.idm.auth.plugin.local;

import android.app.Activity;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.util.Log;
import oracle.idm.auth.plugin.IdmAuthenticationPlugin;
import oracle.idm.auth.plugin.util.PluginErrorCodes;
import oracle.idm.mobile.BaseCheckedException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.auth.local.OMAuthData;
import oracle.idm.mobile.auth.local.OMAuthenticationManager;
import oracle.idm.mobile.auth.local.OMAuthenticationManagerException;
import oracle.idm.mobile.auth.local.OMAuthenticator;
import oracle.idm.mobile.auth.local.OMFingerprintAuthenticator;
import oracle.idm.mobile.auth.local.OMPinAuthenticator;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class handles device based local authentications such as PIN and Fingerprint based.
 * Plugin support local authentication as objects where user can enable any of the supported local authentications.
 * Each such unit is identified by an ID provided by the application.
 * This ID is a mandatory information in this class to perform any operation.
 */
public class LocalAuthentication {
  public LocalAuthentication(Activity mainActivity) {
    this._mainActivity = mainActivity;
    this._context = mainActivity.getApplicationContext();
    try {
      this._sharedManager = OMAuthenticationManager.getInstance(mainActivity.getApplicationContext());
      _init();
    } catch (OMAuthenticationManagerException e) {
      // Nothing we can do to recover here.
      throw new RuntimeException(e);
    }
  }

  /**
   * This method returns the enabled and activated local authentications in primary first order.
   * @param args
   * @param callbackContext
   */
  public void enabledLocalAuthsPrimaryFirst(JSONArray args, CallbackContext callbackContext) {
    try {
      String id = args.optString(0);
      List<String> auths = _getEnabled(id);
      PluginResult result = new PluginResult(PluginResult.Status.OK, new JSONArray(auths));
      callbackContext.sendPluginResult(result);
    } catch (Exception e){
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.GET_ENABLED_AUTHS_ERROR);
    }
  }

  /**
   * Enables local authentication
   * @param args
   * @param callbackContext
   */
  public void enable(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    LocalAuthType type = LocalAuthType.getLocalAuthType(args.optString(1));
    OMAuthData authData = new OMAuthData(args.optString(2));
    OMAuthenticator authenticator = _getAuthenticator(id, type);

    if (authenticator != null) {
      _sendSuccess(callbackContext);
      return;
    }

    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M && type == LocalAuthType.FINGERPRINT) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.FINGERPRINT_NOT_ENABLED);
      return;
    }

    try {
      String instanceId = type.getInstanceId(id);
      _sharedManager.enableAuthentication(type.getName(), instanceId);
      authenticator = _sharedManager.getAuthenticator(type.getName(), instanceId);
      authenticator.initialize(_context, instanceId, null);

      if (type == LocalAuthType.PIN) {
        authenticator.setAuthData(authData);
        authenticator.copyKeysFrom(OMMobileSecurityService.getDefaultAuthenticator(_context).getKeyStore());
      } else if (type == LocalAuthType.FINGERPRINT) {
        OMPinAuthenticator pinAuthenticator = (OMPinAuthenticator) _getAuthenticator(id, LocalAuthType.PIN);
        if (pinAuthenticator == null) {
          IdmAuthenticationPlugin.invokeCallbackError(callbackContext,
                                                      PluginErrorCodes.ENABLE_FINGERPRINT_PIN_NOT_ENABLED);
          return;
        }

        ((OMFingerprintAuthenticator) authenticator).setBackupAuthenticator(pinAuthenticator);
        authenticator.setAuthData(authData);
      }

      _sendSuccess(callbackContext);
    } catch(BaseCheckedException e) {
      Log.e(TAG, "Error while enabling authenticator: " + e.getMessage(), e);
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, e.getErrorCode());
    } catch(Exception e) {
      Log.e(TAG, "Error while enabling authenticator: " + e.getMessage(), e);
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.ERROR_ENABLING_AUTHENTICATOR);
    }
  }

  /**
   * Disables local authenticator
   * @param args
   * @param callbackContext
   */
  public void disable(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    LocalAuthType type = LocalAuthType.getLocalAuthType(args.optString(1));
    OMAuthenticator authenticator = _getAuthenticator(id, type);

    if (authenticator == null) {
      _sendSuccess(callbackContext, _getEnabledPrimary(id));
      _sendSuccess(callbackContext);
      return;
    }

    if (type == LocalAuthType.PIN && _getAuthenticator(id, LocalAuthType.FINGERPRINT) != null) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.DISABLE_PIN_FINGERPRINT_ENABLED);
      return;
    }

    try {
      if (type == LocalAuthType.PIN)
        authenticator.deleteAuthData();

      String instanceId = type.getInstanceId(id);
      _sharedManager.disableAuthentication(type.getName(), instanceId);

      _sendSuccess(callbackContext, _getEnabledPrimary(id));
    } catch(BaseCheckedException e) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, e.getErrorCode());
    }
  }

  /**
   * Authenticates the user using fingerprint.
   * @param args
   * @param callbackContext
   */
  public void authenticateFingerPrint(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    OMFingerprintAuthenticator fingerprintAuthenticator = (OMFingerprintAuthenticator) _getAuthenticator(id, LocalAuthType.FINGERPRINT);

    if (fingerprintAuthenticator == null) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.LOCAL_AUTHENTICATOR_NOT_FOUND);
      return;
    }
    try {
      FingerprintManager.CryptoObject cryptoObject = fingerprintAuthenticator.getFingerprintManagerCryptoObject();
      FingerprintPromptLocalizedStrings strings = createFingerprintPromptLocalizedStrings(args.optJSONObject(1));
      FingerprintAuthenticationDialogFragment fragment = new FingerprintAuthenticationDialogFragment();
      fragment.setData(new FingerprintCallback(fingerprintAuthenticator, callbackContext), cryptoObject, strings);
      fragment.show(_mainActivity.getFragmentManager(), "fingerprintDialogFragment");
    } catch (Exception e) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.AUTHENTICATION_FAILED);
    }
  }

  /**
   * Authenticates the user using PIN
   * @param args
   * @param callbackContext
   */
  public void authenticatePin(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    String pin = args.optString(1);

    OMAuthenticator authenticator = _getAuthenticator(id, LocalAuthType.PIN);

    if (authenticator == null) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.LOCAL_AUTHENTICATOR_NOT_FOUND);
      return;
    }

    if (authenticatePin(authenticator, new OMAuthData(pin), id, callbackContext, PluginErrorCodes.AUTHENTICATION_FAILED))
      _sendSuccess(callbackContext);
  }

  /**
   * This method tries to clean up the fingerprint authenticator, after user
   * has remove his fingerprint enrollment on device.
   * IDM SDK does not do this as of now. So taking care of this at plugin level.
   * Once bug 28682444 is fixed, this can be removed.
   * @param id
   */
  private void _clearUnwantedFingerprintAuthenticator(String id) {
    if (!_clearFingerprintAfterAuthentication)
      return;

    LocalAuthType type = LocalAuthType.FINGERPRINT;
    String instanceId = type.getInstanceId(id);
    try {
      _sharedManager.disableAuthentication(type.getName(), instanceId);
      _clearFingerprintAfterAuthentication = false;
    } catch (OMAuthenticationManagerException e) {
      //  Nothing to do here, simply log.
      Log.e(TAG, "Error while disabling fingerprint since device is not enrolled for it now.", e);
    }
  }

  /**
   * Method used to change PIN.
   * @param args
   * @param callbackContext
   */
  public void changePin(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    String currPin = args.optString(1);
    String newPin = args.optString(2);

    OMAuthenticator authenticator = _getAuthenticator(id, LocalAuthType.PIN);

    if (authenticator == null) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.CHANGE_PIN_WHEN_PIN_NOT_ENABLED);
      return;
    }

    OMAuthData currAuthData = new OMAuthData(currPin);
    if (!authenticatePin(authenticator, currAuthData, id, callbackContext, PluginErrorCodes.INCORRECT_CURRENT_AUTHDATA))
      return;

    try {
      OMAuthData newAuthData = new OMAuthData(newPin);
      authenticator.updateAuthData(currAuthData, newAuthData);
      OMAuthenticator fingerprintAuthenticator = _getAuthenticator(id, LocalAuthType.FINGERPRINT);
      if (fingerprintAuthenticator != null)
        fingerprintAuthenticator.updateAuthData(currAuthData, newAuthData);
      _sendSuccess(callbackContext);
    } catch (BaseCheckedException e) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, e.getErrorCode());
    }
  }

  public void getLocalAuthSupportInfo(JSONArray args, CallbackContext callbackContext) {
    Map<String, String> auths = new HashMap<>();
    auths.put(LocalAuthType.PIN.getName(), FingerprintAvailability.Enrolled.name());
    auths.put(LocalAuthType.FINGERPRINT.getName(), getFingerprintSupportOnDevice().name());
    PluginResult result = new PluginResult(PluginResult.Status.OK, new JSONObject(auths));
    callbackContext.sendPluginResult(result);
  }

  /**
   * Authenticates PIN and does failure callback in case of failure.
   * @param authenticator
   * @param pin
   * @param authId
   * @param callbackContext
   * @param errorCode
   * @return true, if authentication was successful. false, if it was not.
   */
  private boolean authenticatePin(OMAuthenticator authenticator, OMAuthData pin,
                                  String authId, CallbackContext callbackContext,
                                  String errorCode) {
    try {
      authenticator.authenticate(pin);
      _clearUnwantedFingerprintAuthenticator(authId);
      return true;
    } catch (Exception e) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, errorCode);
      return false;
    }
  }

  private FingerprintAvailability getFingerprintSupportOnDevice() {
    // Check if we're running on Android 6.0 (M) or higher
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
      return FingerprintAvailability.NotAvailable;

    FingerprintManager fingerprintManager = (FingerprintManager) this._context.getSystemService(Context.FINGERPRINT_SERVICE);
    if (fingerprintManager.isHardwareDetected()) {
      if (fingerprintManager.hasEnrolledFingerprints())
        return FingerprintAvailability.Enrolled;
      else
        return FingerprintAvailability.NotEnrolled;
    } else {
      return FingerprintAvailability.NotAvailable;
    }
  }

  /**
   * This is to handle an Android specific API issue.
   * In Android, there is a difference between authenticatorName and instanceId.
   * authenticatorName is one per authentication type.
   * After a particular authenticator is registered, we can create multiple instances of it with different instance ids.
   * So, we first register the base authenticators irrespectively.
   */
  private void _init() {
    try {
      _sharedManager.registerAuthenticator(LocalAuthType.PIN.getName(), LocalAuthType.PIN.getAuthClass());
      _sharedManager.enableAuthentication(LocalAuthType.PIN.getName());
    } catch (OMAuthenticationManagerException e) {
      Log.d(TAG, "Base PIN authenticator is already registered.");
    }
    try {
      _sharedManager.registerAuthenticator(LocalAuthType.FINGERPRINT.getName(), LocalAuthType.FINGERPRINT.getAuthClass());
      _sharedManager.enableAuthentication(LocalAuthType.FINGERPRINT.getName());
    } catch (OMAuthenticationManagerException e) {
      Log.d(TAG, "Base FINGERPRINT authenticator is already registered.");
    }
  }

  private OMAuthenticator _getAuthenticator(String id, LocalAuthType type) {
    String instanceId = type.getInstanceId(id);
    Class authClass = type.getAuthClass();

    try {
      OMAuthenticator authenticator = this._sharedManager.getAuthenticator(authClass,
                                                                           instanceId);
      if (!authenticator.isInitialized()) {
        authenticator.initialize(_context,
                                 instanceId,
                                 null);
        if (type == LocalAuthType.FINGERPRINT) {
          OMFingerprintAuthenticator fingerprintAuthenticator = (OMFingerprintAuthenticator) authenticator;
          OMPinAuthenticator pinAuthenticator = (OMPinAuthenticator) _getAuthenticator(id, LocalAuthType.PIN);

          if (pinAuthenticator == null)
            throw new IllegalStateException("Pin authenticator is not expected to be null here.");

          fingerprintAuthenticator.setBackupAuthenticator(pinAuthenticator);
        }
      }

      return authenticator;
    } catch (OMAuthenticationManagerException ignore) {
      Log.d(TAG, String.format("Authenticator with instanceId %s and type %s is not registered. Returning null.", instanceId, authClass.getName()));
      return null;
    }
  }

  private List<String> _getEnabled(String id) {
    OMAuthenticator pinAuthenticator = _getAuthenticator(id, LocalAuthType.PIN);
    OMAuthenticator fingerprintAuthenticator = _getAuthenticator(id, LocalAuthType.FINGERPRINT);
    FingerprintAvailability availability = getFingerprintSupportOnDevice();

    List<String> auths = new ArrayList<>();
    if (fingerprintAuthenticator != null) {
      if (availability == FingerprintAvailability.Enrolled)
        auths.add(LocalAuthType.FINGERPRINT.getName());
      else
        _clearFingerprintAfterAuthentication = true;
    }

    if (pinAuthenticator != null)
      auths.add(LocalAuthType.PIN.getName());

    Log.d(TAG, "Enabled local authentications: " + auths);
    return auths;
  }

  private String _getEnabledPrimary(String id) {
    List<String> enabled = _getEnabled(id);
    if (enabled.size() != 0)
      return enabled.get(0);
    return "";
  }

  private void _sendSuccess(CallbackContext callbackContext) {
    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK));
  }

  private void _sendSuccess(CallbackContext callbackContext, String result) {
    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, result));
  }

  private FingerprintPromptLocalizedStrings createFingerprintPromptLocalizedStrings(JSONObject localizedStrings) {
    FingerprintPromptLocalizedStrings strings = new FingerprintPromptLocalizedStrings();
    if (localizedStrings == null)
      return strings;

    if (!localizedStrings.isNull(PROMPT_MESSAGE))
      strings.setPromptMessage(localizedStrings.optString(PROMPT_MESSAGE));
    if (!localizedStrings.isNull(PIN_FALLBACK_BUTTON_LABEL))
      strings.setPinFallbackButtonLabel(localizedStrings.optString(PIN_FALLBACK_BUTTON_LABEL));
    if (!localizedStrings.isNull(CANCEL_BUTTON_LABEL))
      strings.setCancelButtonLabel(localizedStrings.optString(CANCEL_BUTTON_LABEL));
    if (!localizedStrings.isNull(SUCCESS_MESSAGE))
      strings.setSuccessMessage(localizedStrings.optString(SUCCESS_MESSAGE));
    if (!localizedStrings.isNull(ERROR_MESSAGE))
      strings.setErrorMessage(localizedStrings.optString(ERROR_MESSAGE));
    if (!localizedStrings.isNull(PROMPT_TITLE))
      strings.setPromptTitle(localizedStrings.optString(PROMPT_TITLE));
    if (!localizedStrings.isNull(HINT_TEXT))
      strings.setHintText(localizedStrings.optString(HINT_TEXT));

    return strings;
  }

  private static class FingerprintCallback implements FingerprintAuthenticationDialogFragment.Callback {
    private final OMFingerprintAuthenticator fingerprintAuthenticator;
    private final CallbackContext callbackContext;

    public FingerprintCallback(OMFingerprintAuthenticator fingerprintAuthenticator,
                               CallbackContext callbackContext) {
      this.fingerprintAuthenticator = fingerprintAuthenticator;
      this.callbackContext = callbackContext;
    }


    @Override
    public void onAuthenticated(FingerprintManager.CryptoObject cryptoObject) {
      try {
        fingerprintAuthenticator.authenticate(new OMAuthData(cryptoObject));
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK));
      } catch (OMAuthenticationManagerException e) {
        IdmAuthenticationPlugin.invokeCallbackError(callbackContext, e.getErrorCode());
      }
    }

    @Override
    public void onPinFallback() {
      callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, _FALLBACK));
    }

    @Override
    public void onCancelled() {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.AUTHENTICATION_CANCELLED);
    }
  }

  private enum LocalAuthType {
    FINGERPRINT(_FINGERPRINT_ID, OMFingerprintAuthenticator.class),
    PIN(_PIN_ID, OMPinAuthenticator.class);

    private final String type;
    private final Class authClass;
    LocalAuthType(String type, Class authClass) {
      this.type = type;
      this.authClass = authClass;
    }

    public static LocalAuthType getLocalAuthType(String type) {
      if (PIN.type.equals(type))
        return PIN;
      if (FINGERPRINT.type.equals(type))
        return FINGERPRINT;

      throw new IllegalArgumentException("Unknown local auth type: " + type);
    }

    public Class getAuthClass() {
      return authClass;
    }

    public String getName() {
      return this.type;
    }

    public String getInstanceId(String id) {
      return id + "." + this.type;
    }
  }

  // Availability states for local auth
  private enum FingerprintAvailability { Enrolled, NotEnrolled, NotAvailable };

  private final Activity _mainActivity;
  private final Context _context;
  private final OMAuthenticationManager _sharedManager;
  private boolean _clearFingerprintAfterAuthentication;

  // Localized strings for fingerprint prompt
  private static final String PROMPT_MESSAGE = "promptMessage";
  private static final String PIN_FALLBACK_BUTTON_LABEL = "pinFallbackButtonLabel";
  private static final String CANCEL_BUTTON_LABEL = "cancelButtonLabel";
  private static final String SUCCESS_MESSAGE = "successMessage";
  private static final String ERROR_MESSAGE = "errorMessage";
  private static final String PROMPT_TITLE = "promptTitle";
  private static final String HINT_TEXT = "hintText";

  private static final String _FALLBACK = "fallback";
  private static final String _FINGERPRINT_ID = "cordova.plugins.IdmAuthFlows.Fingerprint";
  private static final String _PIN_ID = "cordova.plugins.IdmAuthFlows.PIN";
  private static final String TAG = LocalAuthentication.class.getSimpleName();
}
