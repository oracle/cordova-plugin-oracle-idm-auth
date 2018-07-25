/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

package oracle.idm.mobile.configuration;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.auth.IdentityContext;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.crypto.CryptoScheme;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.GenericsUtils;
import oracle.idm.mobile.util.StringUtils;

import static oracle.idm.mobile.OMMobileSecurityService.AuthServerType;
import static oracle.idm.mobile.OMMobileSecurityService.OM_AUTO_LOGIN_DEFAULT;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_APPNAME;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_AUTHSERVER_TYPE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_AUTH_KEY;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_AUTO_LOGIN_ALLOWED;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_BROWSER_MODE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_COLLECT_IDENTITY_DOMAIN;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_CONFIRM_LOGOUT_BUTTON_ID;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_CONNECTIVITY_MODE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_CRYPTO_SCHEME;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_CUSTOM_AUTH_HEADERS;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_DEFAULT_PROTOCOL_FOR_CLIENT_SOCKET;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_ENABLED_CIPHER_SUITES;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_HOSTNAME_VERIFICATION;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_IDLE_TIMEOUT_VALUE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_LOCAL_AUTHENTICATOR_INSTANCE_ID;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_LOCAL_AUTHENTICATOR_NAME;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_LOCATION_UPDATE_ENABLED;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_LOGIN_TIMEOUT_VALUE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_LOGOUT_TIMEOUT_VALUE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_MAX_LOGIN_ATTEMPTS;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_OAM_OAUTH_SERVICE_ENDPOINT;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_OAUTH_ENABLE_PKCE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_OAUTH_INCLUDE_CLIENT_AUTH_HEADER;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_OAUTH_SCOPE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_OFFLINE_AUTH_ALLOWED;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_PARSE_TOKEN_RELAY_RESPONSE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_REMEMBER_CREDENTIALS_ALLOWED;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_REMEMBER_USERNAME_ALLOWED;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_REMOVE_ALL_SESSION_COOKIES;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_REQUIRED_TOKENS;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_SEND_AUTHORIZATION_HEADER_IN_LOGOUT;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_SEND_IDENTITY_DOMAIN_HEADER_TO_MOBILE_AGENT;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_SESSION_ACTIVE_ON_RESTART;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_SESSION_TIMEOUT_VALUE;
import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_USERNAME_PARAM_NAME;
import static oracle.idm.mobile.OMMobileSecurityService.OM_REMEMBER_CREDENTIALS_DEFAULT;
import static oracle.idm.mobile.OMMobileSecurityService.OM_REMEMBER_USERNAME_DEFAULT;

/**
 * OMMobileSecurityConfiguration is the abstract base class which provides all
 * the configuration parameters that can be populated by the concrete classes
 * based on the application type.
 *
 */
public abstract class OMMobileSecurityConfiguration {

    public static final String DEFAULT_CONFIGURATION_PROPERTIES_KEY = "OracleIDMMobileSDKConfigurationKey";

    private static final String TAG = OMMobileSecurityConfiguration.class.getSimpleName();

    private static final List<String> PROHIBITED_CUSTOM_AUTH_HEADERS = Arrays
            .asList("authorization", "cookie", "content-length", "host");
    private static final int MAX_CUSTOM_AUTH_HEADERS = 10;

    // Default Values
    private static final int DEFAULT_IDLE_TIMEOUT = 0; // In seconds
    private static final int DEFAULT_SESSION_DURATION = 0; // In seconds
    private static final int DEFAULT_CONNECTION_TIMEOUT = 20; // In seconds
    private static final int DEFAULT_LOGOUT_TIMEOUT = 0; // In seconds
    private static final int DEFAULT_SALT_LENGTH = 8; // In bytes
    private static final String DEFAULT_HEADER_FOR_IDENTITY_DOMAIN = "X-USER-IDENTITY-DOMAIN-NAME";
    private static final int DEFAULT_ADVANCE_TIMEOUT_NOTIFICATION = 10; // In percentage
    public static final HostnameVerification DEFAULT_HOSTNAME_VERIFICATION = HostnameVerification.ALLOW_ALL;

    protected static final String CLAIM_ATTRIBUTES_MSOAUTH = "claimAttributes";
    protected static final String MOBILE_APP_CONFIG = "mobileAppConfig";

    //RC- configuration flags
    //each auth configuration should update the flags for the features they are interested in
    //like basic does honor all three flags but OAuth just required remember username.
    static final int FLAG_ENABLE_AUTO_LOGIN = 1;
    static final int FLAG_ENABLE_REMEMBER_CREDENTIALS = FLAG_ENABLE_AUTO_LOGIN << 1;
    static final int FLAG_ENABLE_REMEMBER_USERNAME = FLAG_ENABLE_AUTO_LOGIN << 2;

    //RC- configuration flags

    /**
     * Refer {@link OMMobileSecurityService#OM_PROP_BROWSER_MODE}
     */
    public enum BrowserMode {
        EMBEDDED("Embedded"), EXTERNAL("External");

        private String value;

        BrowserMode(String value) {
            this.value = value;
        }

        public String getValue() {
            return this.value;
        }

        public static BrowserMode valueOfBrowserMode(String browserMode) {
            for (BrowserMode browserModeEnum : values()) {
                if (browserModeEnum.value.equalsIgnoreCase(browserMode)) {
                    return browserModeEnum;
                }
            }
            return null;
        }
    }

    /**
     * Provides available options to do Hostname verification while establishing
     * HTTPS connection with the server.
     */
    public enum HostnameVerification
    {
        /**
         * This basically disables hostname verification.
         */
        ALLOW_ALL,
        /**
         * The hostname must match either the first CN, or any of the
         * subject-alts. A wildcard can occur in the CN, and in any of the
         * subject-alts.
         */
        STRICT;

        public static HostnameVerification valueOfHostnameVerification(
                String hostnameVerification)
        {
            for (HostnameVerification hostnameVerificationEnum : values())
            {
                if (hostnameVerificationEnum.name().equalsIgnoreCase(
                        hostnameVerification))
                {
                    return hostnameVerificationEnum;
                }
            }
            return null;
        }
    }

    protected OMAuthenticationScheme authenticationScheme;

    protected String applicationId;
    protected URL authenticationUrl;
    protected URL logoutUrl;
    protected Set<String> requiredTokens;
    protected boolean mClientCertificateEnabled = false;

    private OMConnectivityMode connectivityMode = OMConnectivityMode.AUTO;
    private boolean offlineAuthenticationAllowed;
    private int maxFailureAttempts = 3;

    private CryptoScheme cryptoScheme = CryptoScheme.SSHA512;
    private int connectionTimeout = DEFAULT_CONNECTION_TIMEOUT * 1000; // milliseconds
    private int idleTime = DEFAULT_IDLE_TIMEOUT; // seconds
    private int sessionDuration = DEFAULT_SESSION_DURATION; // seconds
    private int advanceTimeoutNotification = DEFAULT_ADVANCE_TIMEOUT_NOTIFICATION; //  percentage


    private String authenticationKey;
    private int saltLength = DEFAULT_SALT_LENGTH;
    private String cryptoMode = "ECB";
    private String cryptoPadding = "PKCS5Padding";
    private int logoutTimeOutValue = DEFAULT_LOGOUT_TIMEOUT;

    private Map<String, String> mCustomHeadersMobileAgent;
    private boolean mSendIdDomainToMobileAgent;
    private boolean mSendCustomAuthHeadersInLogut;
    private boolean mSendAuthzHeaderInLogout;
    // RC
    private boolean remeberCredentialsEnabled = false;
    private boolean rememberUsernameOnlyEnabled = false;
    private boolean autoLoginEnabled = false;
    private boolean defaultValueForAutoLogin = false;
    private boolean defaultValueForRememberCredentials = false;
    private boolean defaultValueForRememberUsername = false;
    private boolean anyRCFeatureEnabled = false;
    // RC

    private boolean authContextPersistenceAllowed = false;

    private String[] mDefaultProtcols;
    protected String[] mEnabledCipherSuites;

    /**
     * This contains the HTTP headers to be added to the request being sent to
     * login URL.
     */
    private Map<String, String> customAuthHeaders;

    protected String identityDomain;
    protected String mIdentityDomainHeaderName;
    protected boolean mIdentityDomainInHeader;
    protected boolean collectIdentityDomain = false;

    protected String mAuthenticatorName;
    protected String mAuthenticatorInstanceId;
    protected boolean isInitialized;
    protected IdentityContext idContext;
    protected List<String> identityClaimAttributes;
    protected boolean locationUpdateEnabled = false;
    protected int locationTimeout = DEFAULT_LOCATION_TIMEOUT; // seconds
    protected OMApplicationProfile applicationProfile;
    static final int DEFAULT_LOCATION_TIMEOUT = 5;
    protected URL logoutSuccessUrl;
    protected URI logoutSuccessUri;
    private URL logoutFailureUrl;
    private boolean confirmLogoutAutomatically;
    private Set<String> confirmLogoutButtonId;
    private boolean removeAllSessionCookies;
    private HostnameVerification hostnameVerification = DEFAULT_HOSTNAME_VERIFICATION;

    public static OMMobileSecurityConfiguration createMobileSecurityConfiguration(Map<String, Object> configProperties) throws OMMobileSecurityException {
        Object serverTypeObj = configProperties.get(OM_PROP_AUTHSERVER_TYPE);
        if (serverTypeObj == null || !(serverTypeObj instanceof OMMobileSecurityService.AuthServerType)) {
            // throw exception as we cannot construct a valid config object
            throw new OMMobileSecurityException(OMErrorCode.INVALID_AUTH_SERVER_TYPE);
        }

        AuthServerType serverType = (AuthServerType) serverTypeObj;

        boolean isOAuthConfig = false;
        if (serverType == AuthServerType.HTTPBasicAuth) {
            return new OMBasicMobileSecurityConfiguration(configProperties);
        } else if (serverType == AuthServerType.CBA) {
            return new OMCBAMobileSecurityConfiguration(configProperties);
        } else if (serverType == AuthServerType.FederatedAuth) {
            return new OMFederatedMobileSecurityConfiguration(configProperties);
        } else if (serverType == AuthServerType.OAuth20) {
            Object oamOAuthServiceEndpointObj = configProperties.get(OM_PROP_OAM_OAUTH_SERVICE_ENDPOINT);
            if (oamOAuthServiceEndpointObj != null) {
                // validation of service endpoint done by the constructor.
                return new OMMSOAuthMobileSecurityConfiguration(configProperties);
            } else {
                return new OMOAuthMobileSecurityConfiguration(configProperties, false);
            }
        } else if (serverType == AuthServerType.OpenIDConnect10) {
            return new OMOICMobileSecurityConfiguration(configProperties);
        } else {
            return null;
        }

    }

    /**
     * This method extracts query component from {@link Intent#getData()}, and
     * reads configuration settings from query string. It returns configuration
     * settings as Map<String, Object> object with parameter name as the key and
     * parameter value as value. Optionally it persists the information in
     * SharedPreferences. All configuration properties are stored in
     * SharedPreferences as JSON object using a default key. The application can
     * choose to store using a different key. The query string has to be of
     * format shown below (parameter and value shall be separated using string
     * "::="). All URL parameters have to be URL encoded using UTF8 Encoding. If
     * URLs are not encoded, query parameters will not be parsed correctly.
     *
     * &lt;scheme&gt;://[host][:port]/?&lt;parameter1&gt;::=&lt;value1&gt;&&lt;
     * parameter2&gt;::=&lt;value2&gt;&...&&lt;parameterN&gt;::=&lt;valueN&gt;
     *
     * This method does not validate any configuration settings but SDK
     * initialization logic validates configuration settings.
     *
     *
     * @param context
     *            context of the calling application. Always pass
     *            {@link Context#getApplicationContext()}.
     * @param intent
     *            {@link Intent} which contains query parameters
     * @param persistInSharedPreferences
     *            Persists in SharedPreferences if this parameter is true
     * @param keyInSharedPreferences
     *            Key name with which to store. If this parameter is null, it
     *            will be stored using a default key
     * @return Map<String, Object> containing configuration settings obtained
     *         from configuration URL. Returns null if {@link Intent#getData()}
     *         did not contain have query parameter or if query parameter format
     *         is invalid
     * @throws OMMobileSecurityException
     *             If configuration properties could not be stored in
     *             SharedPreferences
     *
     */
    public static Map<String, Object> parseConfigurationURI(Context context,
                                                            Intent intent, boolean persistInSharedPreferences,
                                                            String keyInSharedPreferences) throws OMMobileSecurityException {
        return parseConfigurationURI(context, intent,
                persistInSharedPreferences, keyInSharedPreferences, null);
    }

    /**
     * This method extracts query component from {@link Intent#getData()}, and
     * reads configuration settings from query string for the specified set of
     * property strings passed as filters. If null/no filters are passed, all
     * the configuration properties are parsed and extracted. It returns
     * configuration settings as Map<String, Object> object with parameter name
     * as the key and parameter value. Optionally it persists the information in
     * SharedPreferences. All configuration properties are stored in
     * SharedPreferences as JSON object using a default key. The application can
     * choose to store using a different key. The query string has to be of
     * format shown below (parameter and value shall be separated using string
     * "::="). All URL parameters have to be URL encoded using UTF8 Encoding. If
     * URLs are not encoded, query parameters will not be parsed correctly.
     *
     * &lt;scheme&gt;://[host][:port]/?&lt;parameter1&gt;::=&lt;value1&gt;&&lt;
     * parameter2&gt;::=&lt;value2&gt;&...&&lt;parameterN&gt;::=&lt;valueN&gt;
     *
     * This method does not validate any configuration settings but SDK
     * initialization logic validates configuration settings.
     *
     * @param context
     *            context of the calling application. Always pass
     *            {@link Context#getApplicationContext()}.
     * @param intent
     *            {@link Intent} which contains query parameters
     * @param persistInSharedPreferences
     *            Persists in SharedPreferences if this parameter is true
     * @param decodeQuery
     *            perform URL decoding on the query.
     * @param keyInSharedPreferences
     *            Key name with which to store. If this parameter is null, it
     *            will be stored using a default key
     * @return
     * @throws OMMobileSecurityException
     *             If configuration properties could not be stored in
     *             SharedPreferences
     */
    public static Map<String, Object> parseConfigurationURI(Context context,
                                                            Intent intent, boolean persistInSharedPreferences,
                                                            boolean decodeQuery, String keyInSharedPreferences)
            throws OMMobileSecurityException {
        return parseConfigurationURI(context, intent,
                persistInSharedPreferences, decodeQuery,
                keyInSharedPreferences, null);
    }

    /**
     * This method extracts query component from {@link Intent#getData()}, and
     * reads configuration settings from query string for the specified set of
     * property strings passed as filters. If null/no filters are passed, all
     * the configuration properties are parsed and extracted. It returns
     * configuration settings as Map<String, Object> object with parameter name
     * as the key and parameter value. Optionally it persists the information in
     * SharedPreferences. All configuration properties are stored in
     * SharedPreferences as JSON object using a default key. The application can
     * choose to store using a different key. The query string has to be of
     * format shown below (parameter and value shall be separated using string
     * "::="). All URL parameters have to be URL encoded using UTF8 Encoding. If
     * URLs are not encoded, query parameters will not be parsed correctly.
     *
     * &lt;scheme&gt;://[host][:port]/?&lt;parameter1&gt;::=&lt;value1&gt;&&lt;
     * parameter2&gt;::=&lt;value2&gt;&...&&lt;parameterN&gt;::=&lt;valueN&gt;
     *
     * This method does not validate any configuration settings but SDK
     * initialization logic validates configuration settings.
     *
     * @param context
     *            context of the calling application. Always pass
     *            {@link Context#getApplicationContext()}.
     * @param intent
     *            {@link Intent} which contains query parameters
     * @param persistInSharedPreferences
     *            Persists in SharedPreferences if this parameter is true
     * @param keyInSharedPreferences
     *            Key name with which to store. If this parameter is null, it
     *            will be stored using a default key
     * @param filters
     *            Set of property strings to be parsed in the configuration URI
     * @return Map<String, Object> containing configuration settings obtained
     *         from configuration URL. Returns null if {@link Intent#getData()}
     *         did not contain have query parameter or if query parameter format
     *         is invalid
     * @throws OMMobileSecurityException
     *             If configuration properties could not be stored in
     *             SharedPreferences
     *
     */
    public static Map<String, Object> parseConfigurationURI(Context context,
                                                            Intent intent, boolean persistInSharedPreferences,
                                                            String keyInSharedPreferences, Set<String> filters)
            throws OMMobileSecurityException {
        return parseConfigurationURI(context, intent,
                persistInSharedPreferences, false, keyInSharedPreferences,
                filters);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseConfigurationURI(Context context,
                                                             Intent intent, boolean persistInSharedPreferences,
                                                             boolean decodeQuery, String keyInSharedPreferences,
                                                             Set<String> filters) throws OMMobileSecurityException
    {
        if (context == null || intent == null)
        {
            throw new IllegalArgumentException();
        }

        Uri configurationUri = intent.getData();
        Map<String, Object> configPropertiesMap = null;
        if (configurationUri != null)
        {
            String query = configurationUri.getEncodedQuery();
            if (query != null)
            {
                configPropertiesMap = new HashMap<>();
                String[] parameterNameValuePairs = query.split("&");
                boolean isFilteringRequired = false;
                if (filters != null && !filters.isEmpty())
                {
                    isFilteringRequired = true;
                }

                for (String parameterNameValuePair : parameterNameValuePairs)
                {
                    String nameValue[] = parameterNameValuePair.split("::=");

                    if (nameValue.length == 2
                            && (!isFilteringRequired || filters
                            .contains(nameValue[0])))
                    {
                        if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_AUTHSERVER_TYPE))
                        {
                            configPropertiesMap
                                    .put(OM_PROP_AUTHSERVER_TYPE,
                                            AuthServerType
                                                    .valueOfAuthServerType(nameValue[1]));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_BROWSER_MODE))
                        {
                            configPropertiesMap.put(OM_PROP_BROWSER_MODE,
                                    BrowserMode
                                            .valueOfBrowserMode(nameValue[1]));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_COLLECT_IDENTITY_DOMAIN)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_OFFLINE_AUTH_ALLOWED)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_AUTO_LOGIN_ALLOWED)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_AUTO_LOGIN_DEFAULT)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_LOCATION_UPDATE_ENABLED)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_REMEMBER_CREDENTIALS_ALLOWED)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_REMEMBER_CREDENTIALS_DEFAULT)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_REMEMBER_USERNAME_ALLOWED)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_REMEMBER_USERNAME_DEFAULT)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_SESSION_ACTIVE_ON_RESTART)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_OAUTH_INCLUDE_CLIENT_AUTH_HEADER)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_SEND_IDENTITY_DOMAIN_HEADER_TO_MOBILE_AGENT)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_SEND_AUTHORIZATION_HEADER_IN_LOGOUT)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_PARSE_TOKEN_RELAY_RESPONSE)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_OAUTH_ENABLE_PKCE)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_REMOVE_ALL_SESSION_COOKIES))
                        {
                            configPropertiesMap.put(nameValue[0],
                                    Boolean.parseBoolean(nameValue[1]));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_CONNECTIVITY_MODE))
                        {
                            configPropertiesMap
                                    .put(OM_PROP_CONNECTIVITY_MODE,
                                            OMConnectivityMode
                                                    .valueOfOMConnectivityMode(nameValue[1]));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_CRYPTO_SCHEME))
                        {
                            configPropertiesMap.put(OM_PROP_CRYPTO_SCHEME,
                                    CryptoScheme.getCryptoScheme(nameValue[1]));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_IDLE_TIMEOUT_VALUE)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_MAX_LOGIN_ATTEMPTS)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_SESSION_TIMEOUT_VALUE)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_LOGIN_TIMEOUT_VALUE)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_LOGOUT_TIMEOUT_VALUE))
                        {
                            configPropertiesMap.put(nameValue[0],
                                    Integer.parseInt(nameValue[1]));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_REQUIRED_TOKENS))
                        {
                            String[] requiredTokensStr = nameValue[1]
                                    .split(",");
                            configPropertiesMap.put(OM_PROP_REQUIRED_TOKENS,
                                    StringUtils.covertToSet(requiredTokensStr,
                                            decodeQuery));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_OAUTH_SCOPE)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_USERNAME_PARAM_NAME)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_CONFIRM_LOGOUT_BUTTON_ID))
                        {
                            boolean decode = false;
                            if (nameValue[0]
                                    .equalsIgnoreCase(OM_PROP_OAUTH_SCOPE)
                                    || decodeQuery)
                            {
                                decode = true;
                            }

                            String[] valuesStr = nameValue[1].split(",");
                            configPropertiesMap.put(nameValue[0],
                                    StringUtils.covertToSet(valuesStr, decode));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_DEFAULT_PROTOCOL_FOR_CLIENT_SOCKET)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_ENABLED_CIPHER_SUITES))
                        {
                            String[] values = nameValue[1].split(",");
                            if (decodeQuery)
                            {
                                for (int i = 0; i < values.length; i++)
                                {
                                    values[i] = Uri.decode(values[i]);
                                }
                            }
                            configPropertiesMap.put(nameValue[0], values);
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_CUSTOM_AUTH_HEADERS)
                                || nameValue[0]
                                .equalsIgnoreCase(OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT))
                        {
                            String[] headers = nameValue[1].split(",");
                            Map<String, String> map = StringUtils.covertToMap(
                                    headers, decodeQuery);
                            if (!map.isEmpty())
                            {
                                configPropertiesMap.put(nameValue[0], map);
                            }
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE))
                        {
                            configPropertiesMap.put(
                                    OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE,
                                    OAuthAuthorizationGrantType
                                            .valueOfGrantType(nameValue[1]));
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_OAM_OAUTH_SERVICE_ENDPOINT))
                        {
                            configPropertiesMap.put(
                                    OM_PROP_OAM_OAUTH_SERVICE_ENDPOINT,
                                    nameValue[1]);
                        }
                        else if (nameValue[0]
                                .equalsIgnoreCase(OM_PROP_HOSTNAME_VERIFICATION))
                        {
                            configPropertiesMap
                                    .put(OM_PROP_HOSTNAME_VERIFICATION,
                                            HostnameVerification
                                                    .valueOfHostnameVerification(nameValue[1]));
                        }
                        else
                        {
                            // This populates properties of type String in the
                            // Map
                            if (nameValue[0].endsWith("URL")
                                    || nameValue[0].endsWith("Endpoint"))
                            {
                                configPropertiesMap.put(nameValue[0],
                                        Uri.decode(nameValue[1]));
                            }
                            else
                            {
                                if (decodeQuery)
                                {
                                    configPropertiesMap.put(nameValue[0],
                                            Uri.decode(nameValue[1]));
                                }
                                else
                                {
                                    configPropertiesMap.put(nameValue[0],
                                            nameValue[1]);
                                }

                            }
                        }
                    }
                }
            }
            if (configPropertiesMap != null && !configPropertiesMap.isEmpty()
                    && persistInSharedPreferences)
            {
                JSONObject configPropertiesJSON = new JSONObject();
                try
                {
                    for (Map.Entry<String, Object> entry : configPropertiesMap
                            .entrySet())
                    {
                        if (entry.getKey()
                                .equalsIgnoreCase(OM_PROP_OAUTH_SCOPE)
                                || entry.getKey().equalsIgnoreCase(
                                OM_PROP_USERNAME_PARAM_NAME)
                                || entry.getKey().equalsIgnoreCase(
                                OM_PROP_REQUIRED_TOKENS)
                                || entry.getKey().equalsIgnoreCase(
                                OM_PROP_CONFIRM_LOGOUT_BUTTON_ID))
                        {
                            configPropertiesJSON.put(
                                    entry.getKey(),
                                    new JSONArray((Set<String>) entry
                                            .getValue()));
                        }
                        else if (entry.getKey().equalsIgnoreCase(
                                OM_PROP_DEFAULT_PROTOCOL_FOR_CLIENT_SOCKET)
                                || entry.getKey().equalsIgnoreCase(
                                OM_PROP_ENABLED_CIPHER_SUITES))
                        {
                            JSONArray values = new JSONArray();
                            for (String value : (String[]) entry.getValue())
                            {
                                values.put(value);
                            }
                            configPropertiesJSON.put(entry.getKey(), values);
                        }
                        else if (entry.getKey().equalsIgnoreCase(
                                OM_PROP_CUSTOM_AUTH_HEADERS)
                                || entry.getKey()
                                .equalsIgnoreCase(
                                        OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT))
                        {
                            configPropertiesJSON.put(
                                    entry.getKey(),
                                    new JSONObject((Map<String, String>) entry
                                            .getValue()));
                        }
                        else
                        {
                            configPropertiesJSON.put(entry.getKey(),
                                    entry.getValue());
                        }
                    }
                    OMLog.debug(TAG + "_parseConfigurationURI",
                            "JSON to be stored in SharedPreferences: "
                                    + configPropertiesJSON.toString(2));
                    OMCredentialStore credentialStore = new OMCredentialStore(
                            context, null, null);
                    if (keyInSharedPreferences != null)
                    {
                        credentialStore.addConfigurationURI(
                                keyInSharedPreferences,
                                configPropertiesJSON.toString());
                    }
                    else
                    {
                        credentialStore.addConfigurationURI(
                                DEFAULT_CONFIGURATION_PROPERTIES_KEY,
                                configPropertiesJSON.toString());
                    }

                }
                catch (JSONException e)
                {
                    OMLog.error(TAG, e.getMessage(), e);
                    throw new OMMobileSecurityException(
                            OMErrorCode.COULD_NOT_STORE_CONFIGURATION);
                }

            }
        }
        return configPropertiesMap;
    }

    /**
     * This method returns a {@link Map<String , Object>} of the stored
     * previously stored configuration if any. This methods accepts a key for
     * which the initialization configuration is to be returned. Please note
     * that if the key supplied is null the SDK will internally try to return
     * the configuration stored against the default key. If there is no
     * configuration present this method returns null.
     *
     * @param context
     *            context of the calling application. Always pass
     *            {@link Context#getApplicationContext()}.
     * @param key
     *            key for which the configuration is to be retrieved.If the key
     *            passed is null then the SDK uses the default key to retrieve
     *            the stored configuration.
     * @return {@link Map} of the initialization configuration stored against
     *         the key.
     * @throws OMMobileSecurityException
     */
    public static Map<String, Object> getInitializationConfiguration(
            Context context, String key) throws OMMobileSecurityException
    {
        if (context == null)
        {
            throw new IllegalArgumentException("Context can not be null");
        }

        String configurationPropertiesKey;
        if (!TextUtils.isEmpty(key))
        {
            configurationPropertiesKey = key;
        }
        else
            configurationPropertiesKey = DEFAULT_CONFIGURATION_PROPERTIES_KEY;

        try
        {
            return retrieveConfigurationProperties(context,
                    configurationPropertiesKey);
        }
        catch (JSONException e)
        {
            OMLog.error(TAG, e.getMessage(), e);
            throw new OMMobileSecurityException(OMErrorCode.COULD_NOT_RETRIEVE_CONFIGURATION);
        }
    }

    private static Map<String, Object> retrieveConfigurationProperties(
            Context context, String configurationPropertiesKey)
            throws JSONException, OMMobileSecurityException
    {
        if (context == null || configurationPropertiesKey == null
                || configurationPropertiesKey.length() == 0)
        {
            throw new IllegalArgumentException();
        }

        OMCredentialStore credentialStore = new OMCredentialStore(context, null, null);
        String configPropertiesStr = credentialStore
                .getConfigurationURI(configurationPropertiesKey);
        if (configPropertiesStr == null)
        {
            throw new OMMobileSecurityException(OMErrorCode.COULD_NOT_RETRIEVE_CONFIGURATION);
        }

        JSONObject configPropertiesJSON = new JSONObject(configPropertiesStr);
        OMLog.debug(TAG,
                "Configuration properties retrieved from SharedPreferences: "
                        + configPropertiesJSON.toString());
        Map<String, Object> configPropertiesMap = new HashMap<>();
        Iterator<String> iterator = configPropertiesJSON.keys();
        while (iterator.hasNext())
        {
            String key = iterator.next();
            if (key.equals(OM_PROP_AUTHSERVER_TYPE))
            {
                configPropertiesMap.put(OM_PROP_AUTHSERVER_TYPE, AuthServerType
                        .valueOf(configPropertiesJSON.optString(key)));
            }
            else if (key.equals(OM_PROP_BROWSER_MODE))
            {
                configPropertiesMap.put(key, BrowserMode
                        .valueOf(configPropertiesJSON.optString(key)));
            }
            else if (key.equals(OM_PROP_COLLECT_IDENTITY_DOMAIN)
                    || key.equals(OM_PROP_OFFLINE_AUTH_ALLOWED)
                    || key.equals(OM_PROP_AUTO_LOGIN_ALLOWED)
                    || key.equals(OM_AUTO_LOGIN_DEFAULT)
                    || key.equals(OM_PROP_REMEMBER_CREDENTIALS_ALLOWED)
                    || key.equals(OM_REMEMBER_CREDENTIALS_DEFAULT)
                    || key.equals(OM_PROP_REMEMBER_USERNAME_ALLOWED)
                    || key.equals(OM_REMEMBER_USERNAME_DEFAULT)
                    || key.equals(OM_PROP_LOCATION_UPDATE_ENABLED)
                    || key.equals(OM_PROP_SESSION_ACTIVE_ON_RESTART)
                    || key.equals(OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER)
                    || key.equals(OM_PROP_OAUTH_INCLUDE_CLIENT_AUTH_HEADER)
                    || key.equals(OM_PROP_SEND_IDENTITY_DOMAIN_HEADER_TO_MOBILE_AGENT)
                    || key.equals(OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND)
                    || key.equals(OM_PROP_SEND_AUTHORIZATION_HEADER_IN_LOGOUT)
                    || key.equals(OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT)
                    || key.equals(OM_PROP_PARSE_TOKEN_RELAY_RESPONSE)
                    || key.equals(OM_PROP_OAUTH_ENABLE_PKCE)
                    || key.equals(OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY)
                    || key.equals(OM_PROP_REMOVE_ALL_SESSION_COOKIES))
            {
                configPropertiesMap.put(key,
                        configPropertiesJSON.optBoolean(key));
            }
            else if (key.equals(OM_PROP_CONNECTIVITY_MODE))
            {
                configPropertiesMap.put(key, OMConnectivityMode
                        .valueOf(configPropertiesJSON.optString(key)));
            }
            else if (key.equals(OM_PROP_CRYPTO_SCHEME))
            {
                configPropertiesMap.put(key, CryptoScheme
                        .getCryptoScheme(configPropertiesJSON.optString(key)));
            }
            else if (key.equals(OM_PROP_IDLE_TIMEOUT_VALUE)
                    || key.equals(OM_PROP_MAX_LOGIN_ATTEMPTS)
                    || key.equals(OM_PROP_SESSION_TIMEOUT_VALUE)
                    || key.equals(OM_PROP_LOGIN_TIMEOUT_VALUE)
                    || key.equals(OM_PROP_LOGOUT_TIMEOUT_VALUE))
            {
                configPropertiesMap.put(key, configPropertiesJSON.optInt(key));
            }
            else if (key.equals(OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE))
            {
                configPropertiesMap.put(key, OAuthAuthorizationGrantType
                        .valueOf(configPropertiesJSON.optString(key)));
            }
            else if (key.equals(OM_PROP_OAUTH_SCOPE)
                    || key.equals(OM_PROP_USERNAME_PARAM_NAME)
                    || key.equals(OM_PROP_REQUIRED_TOKENS)
                    || key.equals(OM_PROP_CONFIRM_LOGOUT_BUTTON_ID))
            {
                JSONArray valuesJSONArray = configPropertiesJSON
                        .optJSONArray(key);
                Set<String> values = new HashSet<>();
                for (int i = 0; i < valuesJSONArray.length(); i++)
                {
                    /*
                     * Decoding '%'-escaped octets in the given string using the
                     * UTF-8 scheme.
                     */
                    values.add(Uri.decode(valuesJSONArray.optString(i)));
                }
                configPropertiesMap.put(key, values);
            }
            else if (key.equals(OM_PROP_DEFAULT_PROTOCOL_FOR_CLIENT_SOCKET)
                    || key.equals(OM_PROP_ENABLED_CIPHER_SUITES))
            {
                JSONArray jsonArray = configPropertiesJSON.optJSONArray(key);
                String[] values = new String[jsonArray.length()];
                for (int i = 0; i < jsonArray.length(); i++)
                {
                    values[i] = jsonArray.optString(i);
                }
                configPropertiesMap.put(key, values);
            }
            else if (key.equals(OM_PROP_CUSTOM_AUTH_HEADERS)
                    || key.equals(OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT))
            {
                Map<String, String> headers = new HashMap<>();
                JSONObject headerObj = configPropertiesJSON.optJSONObject(key);
                Iterator<String> keys = headerObj.keys();
                while (keys.hasNext())
                {
                    String headerName = keys.next();
                    headers.put(headerName, headerObj.optString(headerName));

                }
                configPropertiesMap.put(key, headers);
            }
            else if (key.equals(OM_PROP_HOSTNAME_VERIFICATION))
            {
                configPropertiesMap.put(key, HostnameVerification
                        .valueOf(configPropertiesJSON.optString(key)));
            }
            else
            {
                // This populates properties of type String in the Map
                configPropertiesMap.put(key,
                        configPropertiesJSON.optString(key));
            }
        }
        return configPropertiesMap;
    }

    /**
     * This method deletes the initialization configuration stored against the
     * provided key. If the key provided is null then the SDK tries to delete
     * the configuration present against the default key maintained by the SDK.
     *
     * @param context
     *            context of the calling application. Always pass
     *            {@link Context#getApplicationContext()}.
     * @param key
     *            key for which the configuration is to be deleted.If the key
     *            passed is null then the SDK uses the default key to delete the
     *            stored configuration.
     * @return true if the deletion happens successfully other wise false.
     */
    public static boolean deleteInitializationConfiguration(Context context,
                                                            String key)
    {
        if (context == null)
        {
            throw new IllegalArgumentException("Context can not be null");
        }
        String configurationPropertiesKey;
        if (!TextUtils.isEmpty(key))
        {
            configurationPropertiesKey = key;
        }
        else {
            configurationPropertiesKey = DEFAULT_CONFIGURATION_PROPERTIES_KEY;
        }
        OMCredentialStore credentialStore = new OMCredentialStore(context, null, null);
        if (credentialStore.getConfigurationURI(configurationPropertiesKey) == null)
        {
            // if no configuration present in the store lets return false.
            return false;
        }
        // delete the stored configuration.
        credentialStore.deleteConfigurationURI(configurationPropertiesKey);
        return true;
    }

    /**
     * This constructor can be used to do any common initialization across
     * implementations.
     *
     * @param configProperties
     */
    protected OMMobileSecurityConfiguration(Map<String, Object> configProperties) throws OMMobileSecurityException {
        Object applicationIdObj = configProperties.get(OM_PROP_APPNAME);
        if (applicationIdObj instanceof String
                && !TextUtils.isEmpty((String) applicationIdObj)) {
            this.applicationId = (String) applicationIdObj;
        } else {
            throw new OMMobileSecurityException(OMErrorCode.INVALID_APP_NAME);
        }

        Object maxFailObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_MAX_LOGIN_ATTEMPTS);

        if (maxFailObj != null && maxFailObj instanceof Integer) {
            this.maxFailureAttempts = (Integer) maxFailObj;
        }

        // get the credential key if it is passed as input
        Object authKeyObj = configProperties.get(OM_PROP_AUTH_KEY);
        if (authKeyObj instanceof String && !TextUtils.isEmpty((String) authKeyObj)) {
            this.authenticationKey = (String) authKeyObj;
        }
 
        /*
        * Configuration for the auth context persistence
        */
        Object sessionActiveOnRestartObject = configProperties
                .get(OM_PROP_SESSION_ACTIVE_ON_RESTART);
        if (sessionActiveOnRestartObject instanceof Boolean) {
            this.authContextPersistenceAllowed = (Boolean) sessionActiveOnRestartObject;
        }

        Object logoutTimeoutObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_LOGOUT_TIMEOUT_VALUE);
        if (logoutTimeoutObj != null && logoutTimeoutObj instanceof Integer) {
            this.logoutTimeOutValue = (Integer) logoutTimeoutObj;
        }

        Object clientCertEnabledObj = configProperties
                .get(OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND);
        if (clientCertEnabledObj instanceof Boolean) {
            this.mClientCertificateEnabled = (Boolean) clientCertEnabledObj;
        }

        Object defaultProtocolsObj = configProperties
                .get(OM_PROP_DEFAULT_PROTOCOL_FOR_CLIENT_SOCKET);
        if (defaultProtocolsObj instanceof String[]) {
            String[] defaultProtocols = (String[]) defaultProtocolsObj;
            if (defaultProtocols.length > 0) {
                this.mDefaultProtcols = defaultProtocols;
            }
        }

        Object enabledCipherSuitesObj = configProperties
                .get(OM_PROP_ENABLED_CIPHER_SUITES);
        if (enabledCipherSuitesObj instanceof String[]) {
            String[] enabledCipherSuites = (String[]) enabledCipherSuitesObj;
            if (enabledCipherSuites.length > 0) {
                this.mEnabledCipherSuites = enabledCipherSuites;
            }
        }


        Object customHeaderMobAgentObj = configProperties
                .get(OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT);
        if (customHeaderMobAgentObj instanceof Map<?, ?>) {
            this.mCustomHeadersMobileAgent = (Map<String, String>) customHeaderMobAgentObj;
        }

        Object sendIdDomainToAgentObj = configProperties
                .get(OM_PROP_SEND_IDENTITY_DOMAIN_HEADER_TO_MOBILE_AGENT);
        if (sendIdDomainToAgentObj instanceof Boolean) {
            this.mSendIdDomainToMobileAgent = (Boolean) sendIdDomainToAgentObj;
        }

        Object authenticatorNameObj = configProperties.get(OM_PROP_LOCAL_AUTHENTICATOR_NAME);
        if (authenticatorNameObj instanceof String) {
            this.mAuthenticatorName = (String) authenticatorNameObj;
        }

        Object authenticatorInstanceIdObj = configProperties.get(OM_PROP_LOCAL_AUTHENTICATOR_INSTANCE_ID);
        if (authenticatorInstanceIdObj instanceof String) {
            this.mAuthenticatorInstanceId = (String) authenticatorInstanceIdObj;
        }
        Object locationUpdateEnabledObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_LOCATION_UPDATE_ENABLED);
        if (locationUpdateEnabledObj != null
                && locationUpdateEnabledObj instanceof Boolean) {
            this.locationUpdateEnabled = (Boolean) locationUpdateEnabledObj;
        }

        Object logoutSuccessUrl = configProperties
                .get(OMMobileSecurityService.OM_PROP_LOGOUT_SUCCESS_URL);
        if (logoutSuccessUrl instanceof URL)
        {
            this.logoutSuccessUrl = (URL) logoutSuccessUrl;
        }
        else if (logoutSuccessUrl instanceof String)
        {
            try {
                this.logoutSuccessUrl = new URL((String) logoutSuccessUrl);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("OM_PROP_LOGOUT_SUCCESS_URL is a malformed URL.", e);
            }
        }

        Object logoutFailureUrl = configProperties
                .get(OMMobileSecurityService.OM_PROP_LOGOUT_FAILURE_URL);
        if (logoutFailureUrl instanceof URL)
        {
            this.logoutFailureUrl = (URL) logoutFailureUrl;
        }
        else if (logoutFailureUrl instanceof String)
        {
            try {
                this.logoutFailureUrl = new URL((String) logoutFailureUrl);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("OM_PROP_LOGOUT_FAILURE_URL is a malformed URL.", e);
            }
        }

        Object confirmLogoutAutomaticallyObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY);

        if (confirmLogoutAutomaticallyObj != null
                && confirmLogoutAutomaticallyObj instanceof Boolean) {
            this.confirmLogoutAutomatically = (Boolean) confirmLogoutAutomaticallyObj;
        }

        Object confirmLogoutButtonIdObj = configProperties.get(OM_PROP_CONFIRM_LOGOUT_BUTTON_ID);
        if (confirmLogoutButtonIdObj != null
                && confirmLogoutButtonIdObj instanceof Set<?>)
        {
            this.confirmLogoutButtonId = GenericsUtils
                    .castToSet((Set<?>) confirmLogoutButtonIdObj, String.class);
            checkElementsEmpty(confirmLogoutButtonId, OM_PROP_CONFIRM_LOGOUT_BUTTON_ID);
        }

        Object removeAllSessionCookiesObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_REMOVE_ALL_SESSION_COOKIES);

        if (removeAllSessionCookiesObj instanceof Boolean)
        {
            this.removeAllSessionCookies = (Boolean) removeAllSessionCookiesObj;
        }

        Object hostNameVerificationObj = configProperties
                .get(OM_PROP_HOSTNAME_VERIFICATION);
        if (hostNameVerificationObj instanceof HostnameVerification)
        {
            this.hostnameVerification = (HostnameVerification) hostNameVerificationObj;
        }
}

    /**
     * Performs the initial setup required for the mobile security sdk.
     *
     * @param context Context of the application to access the resource bundle
     * @throws OMMobileSecurityException if there is any exception
     */
    public abstract void initialize(Context context, OMConnectionHandler handler)
            throws OMMobileSecurityException;

    protected void parseLoginURL(Map<String, Object> configProperties) throws MalformedURLException {
        Object loginUrlObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_LOGIN_URL);

        if (loginUrlObj instanceof URL) {
            this.authenticationUrl = (URL) loginUrlObj;
        } else if (loginUrlObj instanceof String) {
            this.authenticationUrl = new URL((String) loginUrlObj);
        } else {
            throw new IllegalArgumentException("Login url is invalid");
        }
    }

    protected void parseLogoutURL(Map<String, Object> configProperties) throws MalformedURLException {
        Object logoutUrlObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_LOGOUT_URL);

        if (logoutUrlObj instanceof URL) {
            this.logoutUrl = (URL) logoutUrlObj;
        } else if (logoutUrlObj instanceof String) {
            this.logoutUrl = new URL((String) logoutUrlObj);
        } else {
            throw new IllegalArgumentException("Logout url is invalid");
        }
    }

    protected void parseRequiredTokens(Map<String, Object> configProperties) {
        Object requiredTokensObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_REQUIRED_TOKENS);

        if (requiredTokensObj instanceof Set<?>) {
            this.requiredTokens = GenericsUtils.castToSet(
                    (Set<?>) requiredTokensObj, String.class);
        }
    }

    public boolean isInitialized() {
        return isInitialized;
    }


    /**
     * For OAuth, remember credentials flags apart from the remember user name flag wont be entertained. So, remove those entries from the map being passed here.
     *
     * @param configProperties
     */
    protected void parseRememberCredentials(Map<String, Object> configProperties, int flags) {
        boolean anyRCFeatureEnabled = false;

        if ((flags & FLAG_ENABLE_AUTO_LOGIN) != 0) {
            OMLog.info(TAG, "Parsing for auto login config");
            Object autoLoginObject = configProperties
                    .get(OM_PROP_AUTO_LOGIN_ALLOWED);

            if (autoLoginObject != null && autoLoginObject instanceof Boolean) {
                anyRCFeatureEnabled = true;
                this.autoLoginEnabled = (Boolean) autoLoginObject;
            }

            Object defaultAutoLoginObj = configProperties
                    .get(OM_AUTO_LOGIN_DEFAULT);
            if (defaultAutoLoginObj != null) {
                if (defaultAutoLoginObj instanceof Boolean) {
                    this.defaultValueForAutoLogin = (Boolean) defaultAutoLoginObj;
                } else {
                    throw new IllegalArgumentException(
                            "Default value should be a boolean");
                }
            }
        }

        if ((flags & FLAG_ENABLE_REMEMBER_CREDENTIALS) != 0) {
            OMLog.info(TAG, "Parsing for remember credentials config");
            Object rememberCredentialsObject = configProperties
                    .get(OM_PROP_REMEMBER_CREDENTIALS_ALLOWED);
            if (rememberCredentialsObject != null
                    && rememberCredentialsObject instanceof Boolean) {
                anyRCFeatureEnabled = true;
                this.remeberCredentialsEnabled = (Boolean) rememberCredentialsObject;
            }

            Object defaultRememberCredentialObj = configProperties
                    .get(OM_REMEMBER_CREDENTIALS_DEFAULT);
            if (defaultRememberCredentialObj != null) {
                if (defaultRememberCredentialObj instanceof Boolean) {
                    this.defaultValueForRememberCredentials = (Boolean) defaultRememberCredentialObj;
                } else {
                    throw new IllegalArgumentException(
                            "Default value should be a boolean");
                }
            }
        }

        if ((flags & FLAG_ENABLE_REMEMBER_USERNAME) != 0) {
            OMLog.info(TAG, "Parsing for remember username config");
            Object rememberUsernameObject = configProperties
                    .get(OM_PROP_REMEMBER_USERNAME_ALLOWED);
            if (rememberUsernameObject != null
                    && rememberUsernameObject instanceof Boolean) {
                anyRCFeatureEnabled = true;
                this.rememberUsernameOnlyEnabled = (Boolean) rememberUsernameObject;
            }

            Object defaultRememberUsernameObj = configProperties
                    .get(OM_REMEMBER_USERNAME_DEFAULT);
            if (defaultRememberUsernameObj != null) {
                if (defaultRememberUsernameObj instanceof Boolean) {
                    this.defaultValueForRememberUsername = (Boolean) defaultRememberUsernameObj;
                } else {
                    throw new IllegalArgumentException(
                            "Default value should be a boolean");
                }
            }
        }
        this.anyRCFeatureEnabled = (flags != 0);
    }

    protected void parseIdentityDomainProperties(
            Map<String, Object> configProperties) {
        Object collectIdentityDomainObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_COLLECT_IDENTITY_DOMAIN);

        if (collectIdentityDomainObj != null
                && collectIdentityDomainObj instanceof Boolean) {
            collectIdentityDomain = (Boolean) collectIdentityDomainObj;
        }
        String identityName = (String) configProperties
                .get(OMMobileSecurityService.OM_PROP_IDENTITY_DOMAIN_NAME);
        if (identityName != null && identityName.length() != 0) {
            this.identityDomain = identityName;
        }

        Object identityDomainInHeaderObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER);

        if (identityDomainInHeaderObj != null
                && identityDomainInHeaderObj instanceof Boolean) {
            this.mIdentityDomainInHeader = (Boolean) identityDomainInHeaderObj;
        }

        Object identityDomainHeaderNameObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_IDENTITY_DOMAIN_HEADER_NAME);
        if (identityDomainHeaderNameObj != null
                && identityDomainHeaderNameObj instanceof String) {
            this.mIdentityDomainHeaderName = (String) identityDomainHeaderNameObj;
        }
    }

    protected void parseCustomAuthHeaders(
            Map<String, Object> configProperties) {
        Object customAuthHeadersObject = configProperties
                .get(OMMobileSecurityService.OM_PROP_CUSTOM_AUTH_HEADERS);
        if (customAuthHeadersObject != null
                & customAuthHeadersObject instanceof Map<?, ?>) {
            Map<String, String> customAuthHeadersMap = ((Map<String, String>) customAuthHeadersObject);
            if (customAuthHeadersMap.size() > MAX_CUSTOM_AUTH_HEADERS) {
                throw new IllegalArgumentException(
                        "The number of custom auth headers which are specified as part of OM_PROP_CUSTOM_AUTH_HEADERS exceeded the maximum count ("
                                + MAX_CUSTOM_AUTH_HEADERS + ").");

            }

            Set<String> keys = customAuthHeadersMap.keySet();
            for (String key : keys) {
                /*
                 * Since HTTP Headers are case-insensitive, in order to check
                 * against the list of prohibited headers, the headers supplied
                 * are converted to lower case and checked.
                 */
                if (PROHIBITED_CUSTOM_AUTH_HEADERS.contains(key
                        .toLowerCase(Locale.ENGLISH))) {
                    throw new IllegalArgumentException(
                            "Some of the HTTP headers specified in the Map passed as a value against the key OM_PROP_CUSTOM_AUTH_HEADERS cannot be added. Please refer the documentaion for the list of HTTP headers not allowed.");

                }
            }

            this.customAuthHeaders = customAuthHeadersMap;
        }
    }

    protected void parseSendCustomAuthHeadersInLogout(
            Map<String, Object> configProperties) {
        Object prefObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT);
        if (prefObj instanceof Boolean) {
            mSendCustomAuthHeadersInLogut = (Boolean) prefObj;
        }
    }

    protected void parseAuthzHeaderInLogout(
            Map<String, Object> configProperties) {
        Object prefObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_SEND_AUTHORIZATION_HEADER_IN_LOGOUT);
        if (prefObj instanceof Boolean) {
            mSendAuthzHeaderInLogout = (Boolean) prefObj;
        }
    }

    protected void parseOfflinePreferences(
            Map<String, Object> configProperties) {
        Object offlineAuthAlledObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_OFFLINE_AUTH_ALLOWED);

        if (offlineAuthAlledObj != null
                && offlineAuthAlledObj instanceof Boolean) {
            this.offlineAuthenticationAllowed = (Boolean) offlineAuthAlledObj;
        }

        Object connectivityModeObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_CONNECTIVITY_MODE);
        if (connectivityModeObj != null
                && connectivityModeObj instanceof OMConnectivityMode) {
            this.connectivityMode = (OMConnectivityMode) connectivityModeObj;
        } else if (connectivityModeObj instanceof String) {
            this.connectivityMode = OMConnectivityMode.valueOfOMConnectivityMode((String) connectivityModeObj);
        }

        Object authKeyObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_AUTH_KEY);

        if (authKeyObj != null
                && authKeyObj instanceof String) {
            this.authenticationKey = (String) authKeyObj;
        }
        Object cryptoObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_CRYPTO_SCHEME);

        if (cryptoObj != null && cryptoObj instanceof CryptoScheme) {
            this.cryptoScheme = (CryptoScheme) cryptoObj;
        } else if (cryptoObj instanceof String) {
            this.cryptoScheme = CryptoScheme.getCryptoScheme((String) cryptoObj);
        }
    }

    protected void parseIdleTimeout(Map<String, Object> configProperties) throws OMMobileSecurityException {
        Object idleTimeout = configProperties
                .get(OMMobileSecurityService.OM_PROP_IDLE_TIMEOUT_VALUE);

        if (idleTimeout != null && idleTimeout instanceof Integer) {
            this.idleTime = (Integer) idleTimeout;

            Object sessionTimeout = configProperties
                    .get(OMMobileSecurityService.OM_PROP_SESSION_TIMEOUT_VALUE);
            if (sessionTimeout != null && sessionTimeout instanceof Integer) {
                Integer sessionTimeoutInteger = (Integer) sessionTimeout;
                validateTimeout(this.idleTime, sessionTimeoutInteger);
            }
        }

        Object advanceTimeoutNotificationObj = configProperties
                .get(OMMobileSecurityService.OM_PROP_PERCENTAGE_TO_IDLE_TIMEOUT);

        if (advanceTimeoutNotificationObj != null && advanceTimeoutNotificationObj instanceof Integer) {
            Integer advanceTimeoutNotification = (Integer) advanceTimeoutNotificationObj;
            if (advanceTimeoutNotification > 0 && advanceTimeoutNotification < 100) {
                this.advanceTimeoutNotification = advanceTimeoutNotification;
            } else {
                throw new OMMobileSecurityException(OMErrorCode.OUT_OF_RANGE, "The percentage to idle timeout has to be between 0 and 100");
            }

        }
    }

    protected void parseSessionTimeout(Map<String, Object> configProperties) throws OMMobileSecurityException {
        Object sessionTimeout = configProperties
                .get(OMMobileSecurityService.OM_PROP_SESSION_TIMEOUT_VALUE);
        if (sessionTimeout != null && sessionTimeout instanceof Integer) {
            this.sessionDuration = (Integer) sessionTimeout;

            Object idleTimeout = configProperties
                    .get(OMMobileSecurityService.OM_PROP_IDLE_TIMEOUT_VALUE);

            if (idleTimeout != null && idleTimeout instanceof Integer) {
                Integer idleTimeoutInteger = (Integer) idleTimeout;
                validateTimeout(idleTimeoutInteger, this.sessionDuration);
            }
        }
    }

    private void validateTimeout(int idleTimeout, int sessionTimeout) throws OMMobileSecurityException {
        if (idleTimeout >= sessionTimeout) {
            throw new OMMobileSecurityException(OMErrorCode.INVALID_IDLE_SESSION_TIMEOUT_TIME);
        }
    }

    protected void parseClientCertPreference(Map<String, Object> configProperties) {
        Object clientCertObj = configProperties.get(OMMobileSecurityService.OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND);
        if (clientCertObj instanceof Boolean) {
            mClientCertificateEnabled = (boolean) clientCertObj;
        }
    }

    // Getter / Setter Methods
    public int getMaxFailureAttempts() {
        return maxFailureAttempts;
    }

    void setMaxFailureAttempts(int maxFailureAttempts) {
        validate(maxFailureAttempts);
        this.maxFailureAttempts = maxFailureAttempts;
    }

    /**
     * Gets the identity domain
     *
     * @return identity domain
     */
    public String getIdentityDomain() {
        return identityDomain;
    }

    /**
     * Sets the identity domain
     *
     * @param identityDomain the identity domain to set
     */
    void setIdentityDomain(String identityDomain) {
        this.identityDomain = identityDomain;
    }

    public boolean isCollectIdentityDomain() {
        return collectIdentityDomain;
    }

    void setCollectIdentityDomain(boolean collectIdentityDomain) {
        this.collectIdentityDomain = collectIdentityDomain;
    }

    /**
     * Gets the logout timeout value
     *
     * @return logout timeout value in seconds
     */
    public int getLogoutTimeOutValue() {
        return logoutTimeOutValue;
    }

    /**
     * Sets the logout timeout value
     *
     * @param logoutTimeOutValue in seconds
     */
    void setLogoutTimeOutValue(int logoutTimeOutValue) {
        this.logoutTimeOutValue = logoutTimeOutValue;
    }

    public URL getAuthenticationURL() {
        return authenticationUrl;
    }

    public void setAuthenticationURL(URL authenticationUrl) {
        this.authenticationUrl = authenticationUrl;
    }

    public CryptoScheme getCryptoScheme() {
        if (cryptoScheme == null) {
            cryptoScheme = CryptoScheme.SSHA512;
        }
        return cryptoScheme;
    }

    void setCryptoScheme(CryptoScheme cryptoScheme) {
        this.cryptoScheme = cryptoScheme;
    }

    public OMAuthenticationScheme getAuthenticationScheme() {
        return authenticationScheme;
    }

    void setAuthenticationScheme(
            OMAuthenticationScheme authenticationScheme) {
        this.authenticationScheme = authenticationScheme;
    }

    public int getIdleTime() {
        return idleTime;
    }

    void setIdleTime(int idleTime) {
        validate(idleTime);
        this.idleTime = idleTime;
    }

    public int getAdvanceTimeoutNotification() {
        return advanceTimeoutNotification;
    }

    public OMConnectivityMode getConnectivityMode() {
        return connectivityMode;
    }

    void setConnectivityMode(OMConnectivityMode connectivityMode) {
        this.connectivityMode = connectivityMode;
    }

    public boolean isOfflineAuthenticationAllowed() {
        return offlineAuthenticationAllowed;
    }

    void setOfflineAuthenticationAllowed(
            boolean offlineAuthenticationAllowed) {
        this.offlineAuthenticationAllowed = offlineAuthenticationAllowed;
    }

    /**
     * Returns the connection timeout in seconds
     *
     * @return
     */
    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * Sets the connection timeout in seconds
     *
     * @param connectionTimeout
     */
    void setConnectionTimeout(int connectionTimeout) {
        validate(connectionTimeout);
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * Returns the session duration in seconds
     *
     * @return
     */
    public int getSessionDuration() {
        return sessionDuration;
    }

    /**
     * Sets the session duration in seconds
     *
     * @param sessionDuration
     */
    void setSessionDuration(int sessionDuration) {
        validate(sessionDuration);
        this.sessionDuration = sessionDuration;
    }

    public Set<String> getRequiredTokens() {
        if (requiredTokens == null) {
            requiredTokens = new HashSet<>();
        }

        return requiredTokens;
    }

    void setRequiredTokens(Set<String> requiredTokens) {
        this.requiredTokens = requiredTokens;
    }

    public URL getLogoutUrl() {
        return logoutUrl;
    }

    void setLogoutUrl(URL logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public boolean sendIdentityDomainInHeader() {
        return mIdentityDomainInHeader;
    }

    public String getIdentityDomainHeaderName() {
        if (TextUtils.isEmpty(mIdentityDomainHeaderName)) {
            return DEFAULT_HEADER_FOR_IDENTITY_DOMAIN;
        }
        return mIdentityDomainHeaderName;
    }

    public int getSaltLength() {
        return saltLength;
    }

    void setSaltLength(int saltLength) {
        validate(saltLength);
        this.saltLength = saltLength;
    }

    public String getCryptoMode() {
        return cryptoMode;
    }

    void setCryptoMode(String cryptoMode) {
        this.cryptoMode = cryptoMode;
    }

    public String getCryptoPadding() {
        return cryptoPadding;
    }

    void setCryptoPadding(String cryptoPadding) {
        this.cryptoPadding = cryptoPadding;
    }

    public String getAuthenticationKey() {
        return authenticationKey;
    }

    void setAuthenticationKey(String authenticationKey) {
        this.authenticationKey = authenticationKey;
    }

    // RC
    void setAutoLoginEnabled(boolean autoLogin) {
        this.autoLoginEnabled = autoLogin;
    }

    void setRememberCredentialsEnabled(boolean remeberCredentials) {
        this.remeberCredentialsEnabled = remeberCredentials;
    }

    void setRememberUsernameEnabled(boolean rememberUsernameOnly) {
        this.rememberUsernameOnlyEnabled = rememberUsernameOnly;
    }

    public boolean isAutoLoginEnabled() {
        return autoLoginEnabled;
    }

    public boolean isRememberCredentialsEnabled() {
        return remeberCredentialsEnabled;
    }

    public boolean isRememberUsernameEnabled() {
        return rememberUsernameOnlyEnabled;
    }

    void setDefaultValueForAutoLogin(boolean value) {
        this.defaultValueForAutoLogin = value;
    }

    void setDefaultValueForRememberCredentials(boolean value) {
        this.defaultValueForRememberCredentials = value;
    }

    void setDefaultValueForRememberUsername(boolean value) {
        this.defaultValueForRememberUsername = value;
    }

    void setAnyRCFeatureEnabled(boolean value) {
        this.anyRCFeatureEnabled = value;
    }

    public boolean getDefaultValueForAutoLogin() {
        return defaultValueForAutoLogin;
    }

    public boolean getDefaultValueForRememberCredentials() {
        return defaultValueForRememberCredentials;
    }

    public boolean getDefaultValueForRememberUsername() {
        return defaultValueForRememberUsername;
    }

    /**
     * @return
     * @hide
     */
    public boolean isAnyRCFeatureEnabled() {
        return anyRCFeatureEnabled;
    }

    // RC

    /**
     * Internal API that sets the auth context persistence behavior for the
     * current configuration
     *
     * @param value
     */
    void setAuthContextPersistenceAllowed(boolean value) {
        this.authContextPersistenceAllowed = value;
    }

    /**
     * Internal API that returns whether the current configuration allows the
     * auth context persistence or not?
     *
     * @return
     */
    public boolean isAuthContextPersistenceAllowed() {
        return authContextPersistenceAllowed;
    }

    /*
     * Internal API to set whether the client certificate authentication feature
     * is enabled or disabled by the app.
     * 
     * @param enabled
     */
    void setClientCertificateEnabled(boolean enabled) {
        mClientCertificateEnabled = enabled;
    }

    /*
     * Internal API which returns if the application has enabled or disabled the
     * client certificate support.
     * 
     * @return
     */
    public boolean isClientCertificateEnabled() {
        return mClientCertificateEnabled;
    }

    void setDefaultProtocols(String[] protocols) {
        this.mDefaultProtcols = protocols;
    }

    public String[] getDefaultProtocols() {
        return mDefaultProtcols;
    }

    public String[] getEnabledCipherSuites() {
        return mEnabledCipherSuites;
    }

    public void setEnabledCipherSuites(String[] enabledCipherSuites) {
        this.mEnabledCipherSuites = enabledCipherSuites;
    }

    public Map<String, String> getCustomHeadersMobileAgent() {
        if (mCustomHeadersMobileAgent == null) {
            mCustomHeadersMobileAgent = new HashMap<>();
        }
        return mCustomHeadersMobileAgent;
    }

    void setCustomHeadersMobileAgent(Map<String, String> customHeaders) {
        mCustomHeadersMobileAgent = customHeaders;
    }

    public boolean isSendIdDomainToMobileAgent() {
        return mSendIdDomainToMobileAgent;
    }

    void setSendIdDomainToMobileAgent(boolean preference) {
        mSendIdDomainToMobileAgent = preference;
    }

    public boolean isSendCustomAuthHeadersInLogout() {
        return mSendCustomAuthHeadersInLogut;
    }

    public boolean isSendAuthzHeaderInLogout() {
        return mSendAuthzHeaderInLogout;
    }

    public Map<String, String> getCustomAuthHeaders() {
        // since this is an internal method, so we always return a non null
        // value to
        // avoid issues whenever called.

        if (customAuthHeaders == null) {
            customAuthHeaders = new HashMap<>();
        }
        return customAuthHeaders;
    }

    void setCustomAuthHeaders(Map<String, String> customAuthHeaders) {
        this.customAuthHeaders = customAuthHeaders;
    }

    public String getAuthenticatorName() {
        return mAuthenticatorName;
    }

    public String getAuthenticatorInstanceId() {
        return mAuthenticatorInstanceId;
    }

    private void validate(int value) {
        if (value < 0) {
            throw new IllegalArgumentException(
                    "The value cannot be less than 0.");
        }
    }

    public String getApplicationId() {
        return applicationId;
    }

    protected void parseForCustomAuthHeaders(
            Map<String, Object> configProperties) {
        Object customAuthHeadersObject = configProperties
                .get(OMMobileSecurityService.OM_PROP_CUSTOM_AUTH_HEADERS);
        if (customAuthHeadersObject != null & customAuthHeadersObject instanceof Map<?, ?>) {
            Map<String, String> customAuthHeadersMap = ((Map<String, String>) customAuthHeadersObject);
            if (customAuthHeadersMap.size() > MAX_CUSTOM_AUTH_HEADERS) {
                throw new IllegalArgumentException(
                        "The number of custom auth headers which are specified as part of OM_PROP_CUSTOM_AUTH_HEADERS exceeded the maximum count ("
                                + MAX_CUSTOM_AUTH_HEADERS + ").");

            }

            Set<String> keys = customAuthHeadersMap.keySet();
            for (String key : keys) {
                /*
                 * Since HTTP Headers are case-insensitive, in order to check
                 * against the list of prohibited headers, the headers supplied
                 * are converted to lower case and checked.
                 */
                if (PROHIBITED_CUSTOM_AUTH_HEADERS.contains(key
                        .toLowerCase(Locale.ENGLISH))) {
                    throw new IllegalArgumentException(
                            "Some of the HTTP headers specified in the Map passed as a value against the key OM_PROP_CUSTOM_AUTH_HEADERS cannot be added. Please refer the documentaion for the list of HTTP headers not allowed.");

                }
            }
            this.customAuthHeaders = customAuthHeadersMap;
        }
    }

    IdentityContext getIdentityContext(Context context,
                                       OMCredentialStore credStore) {
        if (idContext == null) {
            idContext = new IdentityContext(context, credStore,
                    getIdentityClaimAttributes(), locationUpdateEnabled,
                    locationTimeout);
        }

        return idContext;
    }

    public List<String> getIdentityClaimAttributes() {
        if (identityClaimAttributes == null) {
            identityClaimAttributes = new ArrayList<String>();
        }
        return identityClaimAttributes;
    }

    /**
     * Computes and returns the identity claims for the device.
     *
     * @param context context of the calling application
     * @return JSON formatted string of identity claims
     */
    public String getIdentityClaims(Context context, OMCredentialStore credStore) {
        IdentityContext idContext = getIdentityContext(context, credStore);
        JSONObject idContextJson = idContext.getIdentityClaims();

        OMLog.debug(TAG + "_getIdentityClaims", "getIdentityCliams : "
                + idContextJson.toString());

        return idContextJson.toString();
    }

    /**
     * Returns an instance of {@link OMApplicationProfile} if it is available;
     * otherwise null.
     *
     * @return {@link OMApplicationProfile} instance / null
     */
    public OMApplicationProfile getApplicationProfile() {
        return applicationProfile;
    }

    public URL getLogoutSuccessUrl() {
        return logoutSuccessUrl;
    }

    public URI getLogoutSuccessUri() {
        return logoutSuccessUri;
    }

    public URL getLogoutFailureUrl() {
        return logoutFailureUrl;
    }

    public boolean isConfirmLogoutAutomatically() {
        return confirmLogoutAutomatically;
    }

    public boolean isRemoveAllSessionCookies()
    {
        return removeAllSessionCookies;
    }

    public HostnameVerification getHostnameVerification()
    {
        return hostnameVerification;
    }

    public Set<String> getConfirmLogoutButtonId() {
        if (confirmLogoutButtonId == null) {
            confirmLogoutButtonId = new HashSet<>();
        }
        return confirmLogoutButtonId;
    }

    protected void checkElementsEmpty(Set<String> set, String property) {
        for (String data : set)
        {
            if (data == null
                    || data.trim().equals(""))
            {
                throw new IllegalArgumentException(
                        property + "contains null or empty string which is not allowed.");
            }
        }
    }
}
