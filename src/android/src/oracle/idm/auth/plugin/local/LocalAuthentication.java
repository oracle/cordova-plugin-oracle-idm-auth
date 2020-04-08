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

import oracle.idm.mobile.auth.local.*;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.crypto.OMKeyManagerException;
import oracle.idm.mobile.crypto.OMSecureStorageException;
import oracle.idm.mobile.crypto.OMSecureStorageService;
import java.io.Serializable;

import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class handles device based local authentications such as PIN and biometric based.
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
      OMAuthenticator defAuth = OMMobileSecurityService.getDefaultAuthenticator(_context);
      _defaultSecuredStore = new OMSecureStorageService(_context, defAuth.getKeyStore(), OMCredentialStore.DEFAULT_AUTHENTICATOR_NAME);

      _init();
    } catch (OMAuthenticationManagerException e) {
      // Nothing we can do to recover here.
      throw new RuntimeException(e);
    } catch (OMKeyManagerException e) {
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

    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M && (type == LocalAuthType.BIOMETRIC || type == LocalAuthType.FINGERPRINT)) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.BIOMETRIC_NOT_ENABLED);
      return;
    }

    try {
      String instanceId = type.getInstanceId(id);
      _sharedManager.enableAuthentication(type.getAuthenticatorName(), instanceId);
      authenticator = _getAuthenticator(id, type);
      authenticator.initialize(_context, instanceId, null);

      if (type == LocalAuthType.PIN) {
        authenticator.setAuthData(authData);
        authenticator.copyKeysFrom(OMMobileSecurityService.getDefaultAuthenticator(_context).getKeyStore());
      } else if (type == LocalAuthType.BIOMETRIC || type == LocalAuthType.FINGERPRINT) {
        OMPinAuthenticator pinAuthenticator = (OMPinAuthenticator) _getAuthenticator(id, LocalAuthType.PIN);
        if (pinAuthenticator == null) {
          IdmAuthenticationPlugin.invokeCallbackError(callbackContext,
                                                      PluginErrorCodes.ENABLE_BIOMETRIC_PIN_NOT_ENABLED);
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

    if (type == LocalAuthType.PIN && (_getAuthenticator(id, LocalAuthType.BIOMETRIC) != null || _getAuthenticator(id, LocalAuthType.FINGERPRINT) != null)) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.DISABLE_PIN_BIOMETRIC_ENABLED);
      return;
    }

    try {
      if (type == LocalAuthType.PIN)
        authenticator.deleteAuthData();

      String instanceId = type.getInstanceId(id);
      _sharedManager.disableAuthentication(type.getAuthenticatorName(), instanceId);

      _sendSuccess(callbackContext, _getEnabledPrimary(id));
    } catch(BaseCheckedException e) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, e.getErrorCode());
    }
  }

  /**
   * Authenticates the user using biometric.
   * @param args
   * @param callbackContext
   */
  public void authenticateBiometric(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    String type = args.optString(1);
    OMFingerprintAuthenticator biometricAuthenticator = (OMFingerprintAuthenticator) _getAuthenticator(id, LocalAuthType.getLocalAuthType(type));

    if (biometricAuthenticator == null) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.LOCAL_AUTHENTICATOR_NOT_FOUND);
      return;
    }
    try {
      FingerprintManager.CryptoObject cryptoObject = biometricAuthenticator.getFingerprintManagerCryptoObject();
      FingerprintPromptLocalizedStrings strings = createFingerprintPromptLocalizedStrings(args.optJSONObject(2));
      FingerprintAuthenticationDialogFragment fragment = new FingerprintAuthenticationDialogFragment();
      fragment.setData(new FingerprintCallback(biometricAuthenticator, callbackContext), cryptoObject, strings);
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
   * Fetches the [key,value] data stored in keystore
   * @param args
   * @param callbackContext
   */
  public void getPreference(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    String key = args.optString(1);

    try {
      OMAuthenticator pinAuthenticator = _getAuthenticator(id, LocalAuthType.PIN);

      if (pinAuthenticator == null)
        throw new IllegalStateException("No enabled authenticators.");

      OMSecureStorageService securedService = new OMSecureStorageService(_context,
              pinAuthenticator.getKeyStore(),
              LocalAuthType.PIN.getInstanceId(id));
      Serializable result = securedService.get(key);
      if (result == null)
        throw new IllegalStateException("No key found in PIN secured store, check in default.");

      _sendSuccess(callbackContext, result.toString());
    } catch (Throwable t) {
      Log.w(TAG, "Error fetching key.", t);
      try {
        Serializable result = _defaultSecuredStore.get(key);
        _sendSuccess(callbackContext, result == null ? null : result.toString());
      } catch (OMSecureStorageException e) {
        Log.e(TAG, "Error while fetching key from default storage.", e);
        IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.GETTING_VALUE_FROM_DEFAULT_STORAGE_FAILED);
      }
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, PluginErrorCodes.GETTING_VALUE_FROM_SECURED_STORAGE_FAILED);
    }
  }

  /**
   * Sets the [key,value] data in keystore
   * @param args
   * @param callbackContext
   */
  public void setPreference(JSONArray args, CallbackContext callbackContext) {
    String id = args.optString(0);
    String key = args.optString(1);
    String value = args.optString(2);
    boolean secure = args.optBoolean(3);
    if (!secure) {
      String errorToThrow = PluginErrorCodes.SAVING_VALUE_TO_DEFAULT_STORAGE_FAILED;
      try {
        if (value == null)
          _defaultSecuredStore.delete(key);
        else
          _defaultSecuredStore.store(key, value);

        _sendSuccess(callbackContext);
      } catch (Throwable e) {
        Log.e(TAG, "Error while storing in default storage.", e);
        IdmAuthenticationPlugin.invokeCallbackError(callbackContext, errorToThrow);
      }
    }
    String errorToThrow = PluginErrorCodes.SAVING_VALUE_TO_SECURED_STORAGE_FAILED;
    OMAuthenticator pinAuthenticator = _getAuthenticator(id, LocalAuthType.PIN);

    try {
      if (pinAuthenticator == null) {
        errorToThrow = PluginErrorCodes.NO_LOCAL_AUTHENTICATORS_ENABLED;
        throw new IllegalStateException("No enabled authenticators.");
      }

      OMSecureStorageService securedService = new OMSecureStorageService(_context,
              pinAuthenticator.getKeyStore(),
              LocalAuthType.PIN.getInstanceId(id));

      if (value == null)
        securedService.delete(key);
      else
        securedService.store(key, value);
      _sendSuccess(callbackContext);

    } catch (Throwable e) {
      Log.e(TAG, "Error while storing in secured storage.", e);
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, errorToThrow);
    }
  }

  /**
   * This method tries to clean up the fingerprint authenticator, after user
   * has remove his fingerprint enrollment on device.
   * IDM SDK does not do this as of now. So taking care of this at plugin level.
   * Once bug 28682444 is fixed, this can be removed.
   * @param id
   */
  private void _clearUnwantedFingerprintAuthenticator(String id) {
    if (!_clearFingerprintInstancesAfterAuthentication)
      return;

    try {
      if (_getAuthenticator(id, LocalAuthType.FINGERPRINT) != null)
        _sharedManager.disableAuthentication(LocalAuthType.FINGERPRINT.getAuthenticatorName(), LocalAuthType.FINGERPRINT.getInstanceId(id));
      if (_getAuthenticator(id, LocalAuthType.BIOMETRIC) != null)
        _sharedManager.disableAuthentication(LocalAuthType.BIOMETRIC.getAuthenticatorName(), LocalAuthType.BIOMETRIC.getInstanceId(id));
      _clearFingerprintInstancesAfterAuthentication = false;
    } catch (OMAuthenticationManagerException e) {
      //  Nothing to do here, simply log.
      Log.e(TAG, "Error while disabling biometric since device is not enrolled for it now.", e);
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
      OMAuthenticator fingerprintAuthenticator = _getAuthenticator(id, LocalAuthType.BIOMETRIC);
      if (fingerprintAuthenticator != null)
        fingerprintAuthenticator.updateAuthData(currAuthData, newAuthData);
      _sendSuccess(callbackContext);
    } catch (BaseCheckedException e) {
      IdmAuthenticationPlugin.invokeCallbackError(callbackContext, e.getErrorCode());
    }
  }

  public void getLocalAuthSupportInfo(JSONArray args, CallbackContext callbackContext) {
    Map<String, String> auths = new HashMap<>();
    String fingerprintAvailability = getFingerprintSupportOnDevice().name();
    auths.put(LocalAuthType.BIOMETRIC.getName(), fingerprintAvailability);
    auths.put(LocalAuthType.FINGERPRINT.getName(), fingerprintAvailability);
    auths.put(LocalAuthType.PIN.getName(), Availability.Enrolled.name());
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

  private Availability getFingerprintSupportOnDevice() {
    // Check if we're running on Android 6.0 (M) or higher
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
      return Availability.NotAvailable;

    FingerprintManager fingerprintManager = (FingerprintManager) this._context.getSystemService(Context.FINGERPRINT_SERVICE);
    if (fingerprintManager.isHardwareDetected()) {
      if (fingerprintManager.hasEnrolledFingerprints())
        return Availability.Enrolled;
      else
        return Availability.NotEnrolled;
    } else {
      return Availability.NotAvailable;
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

    for (LocalAuthType type : LocalAuthType.values()) {
      try {
        _sharedManager.registerAuthenticator(type.getAuthenticatorName(),type.getAuthClass());
        _sharedManager.enableAuthentication(type.getAuthenticatorName());
      } catch (OMAuthenticationManagerException e) {
        Log.d(TAG, type.getName() + " authenticator is already registered.");
      }
    }
  }

  private OMAuthenticator _getAuthenticator(String id, LocalAuthType type) {
    Class authClass = type.getAuthClass();
    String instanceId = type.getInstanceId(id);

    try {
      OMAuthenticator authenticator = this._sharedManager.getAuthenticator(authClass,
                                                                           instanceId);

      if (authenticator.isInitialized())
        return authenticator;

      authenticator.initialize(_context,
                               instanceId,
                               null);

      if (type == LocalAuthType.PIN)
        return authenticator;

      OMFingerprintAuthenticator fingerprintAuthenticator = (OMFingerprintAuthenticator) authenticator;
      OMPinAuthenticator pinAuthenticator = (OMPinAuthenticator) _getAuthenticator(id, LocalAuthType.PIN);

      if (pinAuthenticator == null)
        throw new IllegalStateException("Pin authenticator is not expected to be null here.");

      fingerprintAuthenticator.setBackupAuthenticator(pinAuthenticator);
      return authenticator;
    } catch (OMAuthenticationManagerException ignore) {
      Log.d(TAG, String.format("Authenticator with instanceId %s and type %s is not registered. Returning null.", instanceId, authClass.getName()));
      return null;
    }
  }

  private List<String> _getEnabled(String id) {
    OMAuthenticator pinAuthenticator = _getAuthenticator(id, LocalAuthType.PIN);
    OMAuthenticator biometricAuthenticator = _getAuthenticator(id, LocalAuthType.BIOMETRIC);
    OMAuthenticator fingerprintAuthenticator = _getAuthenticator(id, LocalAuthType.FINGERPRINT);
    Availability availability = getFingerprintSupportOnDevice();

    List<String> auths = new ArrayList<>();

    if (availability != Availability.Enrolled) {
      _clearFingerprintInstancesAfterAuthentication = true;
    } else {
      if (biometricAuthenticator != null)
        auths.add(LocalAuthType.BIOMETRIC.getName());
      if (fingerprintAuthenticator != null)
        auths.add(LocalAuthType.FINGERPRINT.getName());
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
    BIOMETRIC(_BIOMETRIC_ID, _FINGERPRINT_ID, OMFingerprintAuthenticator.class),
    FINGERPRINT(_FINGERPRINT_ID, _FINGERPRINT_ID, OMFingerprintAuthenticator.class),
    PIN(_PIN_ID, _PIN_ID, OMPinAuthenticator.class);

    private final String type;
    private final String authenticatorName;
    private final Class authClass;
    LocalAuthType(String type, String authenticatorName, Class authClass) {
      this.type = type;
      this.authenticatorName = authenticatorName;
      this.authClass = authClass;
    }

    public static LocalAuthType getLocalAuthType(String type) {
      if (PIN.type.equals(type))
        return PIN;
      if (FINGERPRINT.type.equals(type))
        return FINGERPRINT;
      if (BIOMETRIC.type.equals(type))
        return BIOMETRIC;

      throw new IllegalArgumentException("Unknown local auth type: " + type);
    }

    public Class getAuthClass() {
      return authClass;
    }

    public String getName() {
      return this.type;
    }

    public String getAuthenticatorName() {
      return authenticatorName;
    }

    public String getInstanceId(String id) {
      return id + "." + this.type;
    }
  }

  // Availability states for local auth
  private enum Availability { Enrolled, NotEnrolled, NotAvailable };

  private final Activity _mainActivity;
  private final Context _context;
  private final OMAuthenticationManager _sharedManager;
  private boolean _clearFingerprintInstancesAfterAuthentication;
  private final OMSecureStorageService _defaultSecuredStore;

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
  private static final String _BIOMETRIC_ID = "cordova.plugins.IdmAuthFlows.Biometric";
  private static final String _PIN_ID = "cordova.plugins.IdmAuthFlows.PIN";
  private static final String TAG = LocalAuthentication.class.getSimpleName();
}
