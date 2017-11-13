/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.ProtocolException;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.certificate.ClientCertificatePreference;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.connection.OMCookieManager.SET_COOKIE2_HEADER;
import static oracle.idm.mobile.connection.OMCookieManager.SET_COOKIE_HEADER;

/**
 * OMConnectionHandler class which handles all the connections to the server
 *
 * @since 11.1.2.3.1
 */
public class OMConnectionHandler {
//    TODO Consider Code re-factoring and resuage in the http methods.
    private static final String TAG = OMConnectionHandler.class.getSimpleName();
    private static final String HTTP_GET = "GET";
    private static final String HTTP_POST = "POST";
    private static final String HTTP_PUT = "PUT";
    private static final String HTTP_PATCH = "PATCH";
    private static final String HTTP_DELETE = "DELETE";
    private static final String PROTOCOL_HTTP = "http";
    private static final String PROTOCOL_HTTPS = "https";
    private static final String HEADER_FIELD_LOCATION = "Location";
    private static final String HEADER_FIELD_CONTENT = "Content-Type";
    private static final int DEFAULT_CONNECTION_TIMEOUT = 30;//in seconds
    private static String DEFAULT_SSL_PROTOCOL = "TLS";
    private int mConnectionTimeout = DEFAULT_CONNECTION_TIMEOUT * 1000;//in milli seconds
    private final int mReadTimeout = mConnectionTimeout;//for now.
    private final Context mContext;
    private OMCertificateService mCertificateService;
    private OMAuthenticator mPwdAuthenticator;
    private OMSSLSocketFactory mSocketFactory;
    private boolean mHandleClientCerts = false;//to be changed to false TODO
    private String[] mCorrectedProtocols = null;
    private String mDefaultProtocol = "TLSv1.1";
    private boolean mAllowHttpsToHttpRedirect = false;
    private boolean mAllowHttpToHttpsRedirect = true;/*We are by default allowing this configuration*/

    public OMConnectionHandler(Context context) {
        mContext = context;
    }

    /**
     * TODO public doc
     *
     * @param context
     * @param milliSeconds
     */
    public OMConnectionHandler(Context context, int milliSeconds) {
        //TODO see if this really required? or having a setter will suffice.
        this(context);
        if (milliSeconds > 0) {
            mConnectionTimeout = milliSeconds;
        }
    }


    public OMConnectionHandler(Context context, int milliSeconds, boolean handleClientCerts) {
        this(context, milliSeconds);
        mHandleClientCerts = handleClientCerts;
    }

    /**
     * This methods performs HTTP Basic authentication against the given url.
     *
     * @param url
     * @param username
     * @param pwd
     * @param headers
     */
    public String httpGet(URL url, String username, String pwd, Map<String, String> headers) throws OMMobileSecurityException {
        validateURL(url);

        OMHTTPResponse response = httpGet(url, username, pwd, headers, false, (OMHTTPRequest.REQUIRE_RESPONSE_STRING | OMHTTPRequest.REQUIRE_RESPONSE_CODE));
        if (response != null) {
            int responseCode = response.getResponseCode();
            if (responseCode / 100 == 2) {
                //success.
                return response.getResponseStringOnSuccess();
            }
            return response.getResponseStringOnFailure();
        }
        return null;
    }

    /**
     * //TODO require TEST.
     *
     * @param url
     * @param username
     * @param pwd
     * @param headers
     * @param retryRequest
     * @param flags        Refer to OMHTTPRequest for available flags.
     * @return
     * @hide
     */
    public OMHTTPResponse httpGet(URL url, String username, String pwd, Map<String, String> headers, boolean retryRequest, int flags) throws OMMobileSecurityException {
        validateURL(url);
        return httpGet(url, username, pwd, headers, retryRequest, ((flags & OMHTTPRequest.AUTHENTICATION_REQUEST) != 0), ((flags & OMHTTPRequest.REQUIRE_RESPONSE_CODE) != 0), ((flags & OMHTTPRequest.REQUIRE_RESPONSE_STRING) != 0), ((flags & OMHTTPRequest.REQUIRE_RESPONSE_HEADERS) != 0));
    }

    /**
     * @param url
     * @param headers
     * @return
     * @throws OMMobileSecurityException
     */

    public OMHTTPResponse httpGet(final URL url, Map<String, String> headers) throws OMMobileSecurityException {

        validateURL(url);
        return httpGet(url, null, null, headers, false, false, true, true, true);

    }

    /**
     * TODO add public doc
     *
     * @param url
     * @param headers
     * @param payload
     * @param payloadType
     * @return
     */

    public String httpPost(URL url, final Map<String, String> headers, String payload, String payloadType) throws OMMobileSecurityException {

        validateURL(url);

        OMHTTPResponse response = httpPost(url, headers, payload, payloadType, (OMHTTPRequest.REQUIRE_RESPONSE_CODE | OMHTTPRequest.REQUIRE_RESPONSE_STRING));
        if (response != null) {
            int responseCode = response.getResponseCode();
            if (responseCode / 100 == 2) {
                //success
                return response.getResponseStringOnSuccess();
            }
            return response.getResponseStringOnFailure();
        }
        return null;
    }

    public String httpPatch(URL url, final Map<String, String> headers, String payload, String payloadType) throws OMMobileSecurityException {

        validateURL(url);

        OMHTTPResponse response = httpPatch(url, headers, payload, payloadType, (OMHTTPRequest.REQUIRE_RESPONSE_CODE | OMHTTPRequest.REQUIRE_RESPONSE_STRING));
        if (response != null) {
            int responseCode = response.getResponseCode();
            if (responseCode / 100 == 2) {
                //success
                return response.getResponseStringOnSuccess();
            }
            return response.getResponseStringOnFailure();
        }
        return null;
    }

    public OMHTTPResponse httpDelete(URL url, final Map<String, String> headers, String payload, String payloadType) throws OMMobileSecurityException {

        validateURL(url);

        OMHTTPResponse response = httpDelete(url, headers, payload, payloadType, (OMHTTPRequest.REQUIRE_RESPONSE_CODE | OMHTTPRequest.REQUIRE_RESPONSE_STRING));
        if (response != null) {
            return response;
        }
        return null;
    }

    public void setAllowHttpsToHttpRedirect(boolean flag) {
        OMLog.debug(TAG, "setAllowHttpsToHttpRedirect : " + flag);
        mAllowHttpsToHttpRedirect = flag;
    }

    public void setAllowHttpToHttpsRedirect(boolean flag) {
        OMLog.debug(TAG, "setAllowHttpToHttpsRedirect : " + flag);
        mAllowHttpToHttpsRedirect = flag;
    }

    /**
     * //TODO add public doc.
     *
     * @param url
     * @param headers
     * @param payload
     * @param payloadType
     * @return
     * @hide
     */
    public OMHTTPResponse httpPost(URL url, final Map<String, String> headers, String payload, String payloadType, int flags) throws OMMobileSecurityException {
        validateURL(url);
        //right now its headers, we may expect other request preferences in future.
        boolean responseHeadersRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_HEADERS) != 0);
        boolean responseCodeRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_CODE) != 0);
        boolean responseStringRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_STRING) != 0);

        return executeHttpRequest(HTTP_POST, url, headers, payload, payloadType, responseCodeRequired, responseStringRequired, responseHeadersRequired);
    }

    public OMHTTPResponse httpPut(URL url, final Map<String, String> headers, String payload, String payloadType, int flags) throws OMMobileSecurityException {

        validateURL(url);
        //right now its headers, we may expect other request preferences in future.
        boolean responseHeadersRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_HEADERS) != 0);
        boolean responseCodeRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_CODE) != 0);
        boolean responseStringRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_STRING) != 0);
        return executeHttpRequest(HTTP_PUT, url, headers, payload, payloadType, responseCodeRequired, responseStringRequired, responseHeadersRequired);
    }


    //internal;
    private OMHTTPResponse httpGet(final URL url, final String username, final String pwd, Map<String, String> headers,
                                   boolean retryRequest, boolean isAuthMode, boolean requireResponseCode,
                                   boolean requireResponseString, boolean requireHeaders) throws OMMobileSecurityException {
        OMLog.trace(TAG, "httpGet URL              : " + url.toString());
        // extra info only to be logged if required.
        OMLog.info(TAG, "is authentication mode    : " + isAuthMode);
        OMLog.info(TAG, "Response headers required : " + requireHeaders);
        OMLog.info(TAG, "Response code required    : " + requireResponseCode);
        OMLog.info(TAG, "Response string required  : " + requireResponseString);

        if (shouldSetCookieManager()) {
            CookieHandler.setDefault(OMCookieManager.getInstance());
        }
        HttpURLConnection connection;
        InputStream inputStream = null;
        Map<String, List<String>> visitedUrlsCookiesMap = new HashMap();
        boolean isHttps = url.getProtocol().equals(PROTOCOL_HTTPS);
        try {
            if (isHttps) {
                try {
                    connection = getSecureUrlConnection(url);
                } catch (GeneralSecurityException gse) {
                    // secure connection not created.
                    OMLog.error(TAG, "gse.getMessage() " + gse.getMessage());
                    throw new OMMobileSecurityException(OMErrorCode.UNABLE_OPEN_SECURE_CONNECTION);
                }
            } else {
                connection = getUrlConnection(url);
            }
        } catch (IOException ioe) {
            //unable to create the connection.
            throw new OMMobileSecurityException(OMErrorCode.UNABLE_OPEN_CONNECTION);
        }
        if (connection != null) {
            //disabling caching as i encountered that JSession ID was sent in subsequent calls, returning in invalid authentication URL.
            connection.setUseCaches(false);
            addHeaders(connection, headers);
            try {
                connection.setRequestMethod(HTTP_GET);
            } catch (ProtocolException e) {
                e.printStackTrace();
            }
            if (!TextUtils.isEmpty(username) && !TextUtils.isEmpty(pwd)) {
                mPwdAuthenticator = new OMAuthenticator(username, pwd.toCharArray());
                //set authenticator impl for connection system.
                Authenticator.setDefault(mPwdAuthenticator);
            }
            OMHTTPResponse response = new OMHTTPResponse();
            boolean readResponse = false;
            try {
                connection.connect();
                int responseCode = connection.getResponseCode();
                visitedUrlsCookiesMap.putAll(parseCookieFromResponseHeader(connection.getHeaderFields(), connection.getURL()));
                OMLog.trace(TAG, "response code before processing : " + responseCode);
                boolean process = true;
                while (process) {
                    switch (responseCode) {
                        case HttpURLConnection.HTTP_OK:
                        case HttpURLConnection.HTTP_CREATED:
                        case HttpURLConnection.HTTP_ACCEPTED:
                            process = false;
                            if (isAuthMode && !mPwdAuthenticator.isAuthenticationRequired()) {
                                OMLog.error(TAG, "invalid Basic Auth URL");
                                throw new OMMobileSecurityException(OMErrorCode.INVALID_BASIC_AUTHENTICATION_URL);
                                //invalid basic authentication URL
                            } else {
                                //handle success case.
                                readResponse = true;
                            }
                            break;
                        case HttpURLConnection.HTTP_MOVED_TEMP:
                        case HttpURLConnection.HTTP_MOVED_PERM:
                            connection = processForRedirect(url, connection, visitedUrlsCookiesMap);
                            responseCode = connection.getResponseCode();
                            break;
                        case HttpURLConnection.HTTP_UNAUTHORIZED:
                            //Wrong credentials submitted.
                            OMLog.error(TAG, "Wrong credentials");
                            throw new OMMobileSecurityException(OMErrorCode.UN_PWD_INVALID, new InvalidCredentialEvent());
                        case HttpURLConnection.HTTP_NOT_FOUND:
                            OMLog.error(TAG, "The requested URL does not exist");
                            throw new OMMobileSecurityException(OMErrorCode.NOT_FOUND);
                        default:
                            //can handle more specific cases if we want.
                            process = false;
                    }
                }
                OMLog.trace(TAG, "response code after processing : " + responseCode);
                //reading the stream any way as it helps in connection clean up and reuse of the connection in the pool
                //http://docs.oracle.com/javase/1.5.0/docs/guide/net/http-keepalive.html
                if (readResponse) {
                    inputStream = connection.getInputStream();
                    response.setResponseStringOnSuccess(readInputStreamString(inputStream));
                } else {
                    inputStream = connection.getErrorStream();
                    response.setResponseStringOnFailure(readInputStreamString(inputStream));
                }
                if (requireHeaders) {
                    response.setResponseHeaders(connection.getHeaderFields());
                }
                if (requireResponseCode) {
                    response.setResponseCode(responseCode);
                }
                response.setVisitedUrlsCookiesMap(visitedUrlsCookiesMap);

            } catch (SocketException se) {
                if (retryRequest) {
                    //lets release this connection first.
                    connection.disconnect();
                    httpGet(url, username, pwd, headers, false, isAuthMode, requireResponseCode, requireResponseString, requireHeaders);
                }
                throw new OMMobileSecurityException(OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER, se);
            } catch (IOException e) {
                if (e instanceof SSLHandshakeException) {
                    OMLog.error(TAG, "SSLHandshakeException");
                    if (connection instanceof HttpsURLConnection) {
                        handleSSLHandShakeException((HttpsURLConnection) connection, (SSLHandshakeException) e);
                    } else {
                        OMLog.info(TAG, "SSLHandshake error for non HttpsUrlConnection!!");
                        throw new OMMobileSecurityException(OMErrorCode.UNEXPECTED_SSL_FAILURE, e);
                    }
                } else if (e instanceof SSLException) {
                    OMLog.error(TAG, "SSLException");
                    throw new OMMobileSecurityException(OMErrorCode.SSL_EXCEPTION, e);
                } else if (e instanceof ProtocolException && (isAuthMode && mPwdAuthenticator.isAuthenticationRequired)) {
                    //system on getting wrong credentials redirects multiple times due to which this exception occurs.
                    //need to check if this is client issue or server issue.
                    Log.e(TAG, e.getMessage(), e);
                    throw new OMMobileSecurityException(OMErrorCode.AUTHENTICATION_FAILED, new InvalidCredentialEvent());
                } else {
                    OMLog.error(TAG, "IOException ", e);
                    throw new OMMobileSecurityException(OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER, e);
                }
            } catch (GeneralSecurityException gse) {
                OMLog.error(TAG, "Unable open secure connection.");
                throw new OMMobileSecurityException(OMErrorCode.UNABLE_OPEN_SECURE_CONNECTION, gse);
            } finally {
                if (inputStream != null) {
                    try {
                        inputStream.close();
                    } catch (IOException e) {
                        //Do nothing
                    }
                }
                OMLog.info(TAG, "disconnecting...");
                connection.disconnect();
            }
            return response;
        } else {
            OMLog.error(TAG, "Unable to create connection!");
            throw new OMMobileSecurityException(OMErrorCode.UNABLE_OPEN_CONNECTION);
        }
    }

    private void handleSSLHandShakeException(HttpsURLConnection connection, SSLHandshakeException e) throws OMMobileSecurityException {
        OMLog.debug(TAG, "handling SSLHandShakeException");
        OMSSLSocketFactory socketFactory = ((OMSSLSocketFactory) connection.getSSLSocketFactory());
        if (socketFactory.isServerCertUntrusted()) {
            //handle one way ssl;
            OMLog.info(TAG, "Creating SSLExceptionEvent");
            SSLExceptionEvent event = new SSLExceptionEvent(socketFactory.getUntrustedServerCertChain(), socketFactory.getAuthType());
            throw new OMMobileSecurityException(OMErrorCode.SSL_EXCEPTION, event, e);
        } else if (socketFactory.isClientCertRequired()) {
            OMLog.info(TAG, "Creating CBAExceptionEvent");
            CBAExceptionEvent event = new CBAExceptionEvent(socketFactory.getIssuers(), socketFactory.getPeerHost(), socketFactory.getPeerPort(), socketFactory.getKeyTypes());
            throw new OMMobileSecurityException(OMErrorCode.SSL_EXCEPTION, event, e);
        }
        OMLog.info(TAG, "Client Certificate not enabled, hence failing!");
        throw new OMMobileSecurityException(OMErrorCode.SSL_EXCEPTION, e);
    }

    /**
     * @param protocols
     * @hide
     */
    public void setDefaultSSLProtocols(String[] protocols) {
        if (protocols != null) {
            mCorrectedProtocols = protocols;
            OMLog.debug(TAG, "setting default SSL protocols");
            for (String s : mCorrectedProtocols) {
                OMLog.info(TAG, "Corrected to protocol : " + s);
            }
        }
    }

    /**
     * @hide
     */
    public static void setDefaultSSLProtocol(String protocol) {
        validateProtocol(protocol);
        DEFAULT_SSL_PROTOCOL = protocol;
    }

    private static void validateProtocol(String protocol) {

        //validate TLS, TLSv1.1, TLSv1.2 and Default
        boolean valid = false;
        if (protocol != null && (protocol.equalsIgnoreCase("TLS") || protocol.equalsIgnoreCase("TLSv1") || protocol.equals("TLSv1.1") || protocol.equals("TLSv1.2"))) {
            valid = true;
        }
        if (!valid) {
            throw new IllegalArgumentException("Protocol not supported by SDK.");
        }
    }

    public void setClientCertificatePreference(ClientCertificatePreference preference) {
        if (mSocketFactory != null) {
            mSocketFactory.setClientCertificatePreference(preference);
        }
    }

    /**
     * Authenticator impl for basic auth.
     *
     */
    private class OMAuthenticator extends Authenticator {

        private final String localTAG = TAG + "." + OMAuthenticator.class.getSimpleName();
        private boolean isAuthenticationRequired = false;
        private final String aUsername;
        private final char[] aPassword;

        OMAuthenticator(String username, char[] pwd) {
            aUsername = username;
            aPassword = pwd;
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            if (!isAuthenticationRequired) {
                isAuthenticationRequired = true;
                return new PasswordAuthentication(aUsername, aPassword);
            } else {
                return null;
            }
        }

        public boolean isAuthenticationRequired() {
            OMLog.trace(localTAG, "isAuthenticationRequired: " + isAuthenticationRequired);
            return isAuthenticationRequired;
        }
    }

    private HttpURLConnection processForRedirect(URL resourceURL, HttpURLConnection connection, Map<String, List<String>> visitedUrlsCookiesMap) throws GeneralSecurityException, OMMobileSecurityException, IOException {
        int responseCode;
        boolean follow = true;
        boolean isHttps;
        while (follow) {
            String redirectedTo = connection.getHeaderField(HEADER_FIELD_LOCATION);

            try {
                URL redirectedURL = new URL(resourceURL, redirectedTo);
                OMLog.debug(TAG, "Redirected to URL: " + redirectedTo);
                validateRedirect(resourceURL, redirectedURL);
                isHttps = redirectedURL.getProtocol().equals(PROTOCOL_HTTPS);
                if (isHttps) {
                    connection = getSecureUrlConnection(redirectedURL);
                } else {
                    connection = getUrlConnection(redirectedURL);
                }
            } catch (IOException e) {
                //URL opening based error lets not propagate this UP.
                throw new OMMobileSecurityException(OMErrorCode.UNABLE_OPEN_CONNECTION, e);
            }
            try {
                responseCode = connection.getResponseCode();
                visitedUrlsCookiesMap.putAll(parseCookieFromResponseHeader(connection.getHeaderFields(), connection.getURL()));
                switch (responseCode) {
                    case HttpURLConnection.HTTP_MOVED_PERM:
                    case HttpURLConnection.HTTP_MOVED_TEMP:
                        //TODO see if we need to maintain this count.
                        continue;
                    default:
                        follow = false;
                        break;
                }
            } catch (IOException e) {
                if (isHttps) {
                    if (e instanceof SSLHandshakeException) {
                        handleSSLHandShakeException((HttpsURLConnection) connection, (SSLHandshakeException) e);//this may throw OMSE for (1/2 -way SSL events) if applicable
                    }
                }
                throw e;//can be propagated up for common handling
            }
        }
        return connection;
    }

    private void validateRedirect(URL from, URL to) throws OMMobileSecurityException {
        //check for protocol changes
        String fromProtocol = from.getProtocol();
        String toProtocol = to.getProtocol();
        boolean valid = false;
        if (!fromProtocol.equalsIgnoreCase(toProtocol)) {
            OMLog.error(TAG, "Redirected to URL : " + to);
            OMLog.error(TAG, "Redirection Protocol: " + fromProtocol + " -> " + toProtocol);
            InvalidRedirectExceptionEvent.Type type;
            if (PROTOCOL_HTTPS.equalsIgnoreCase(toProtocol)) {
                type = InvalidRedirectExceptionEvent.Type.HTTP_TO_HTTPS;
                if (mAllowHttpToHttpsRedirect) {
                    valid = mAllowHttpToHttpsRedirect;
                }
            } else if (PROTOCOL_HTTP.equalsIgnoreCase(toProtocol)) {
                type = InvalidRedirectExceptionEvent.Type.HTTPS_TO_HTTP;
                valid = mAllowHttpsToHttpRedirect;
            } else {
                type = InvalidRedirectExceptionEvent.Type.UNKNOWN;
                valid = false;
            }
            if (!valid) {
                OMLog.info(TAG, "Creating InvalidRedirect Exception Event");
                throw new OMMobileSecurityException(OMErrorCode.INVALID_REDIRECTION_PROTOCOL_MISMATCH, new InvalidRedirectExceptionEvent(type));
            }
        }
        OMLog.info(TAG, "Valid Redirection " + from + " -> " + to);
    }

    private OMHTTPResponse executeHttpRequest(String httpMethod, URL url, Map<String, String> headers, String payload, String payloadType, boolean requireResponseCode, boolean requireResponseString, boolean requireResponseHeaders) throws OMMobileSecurityException {
        OMLog.debug(TAG, " http method              : " + httpMethod);
        OMLog.trace(TAG, " http request URL              : " + url.toString());
        // extra info only to be logged if required.
        OMLog.info(TAG, "Response headers required : " + requireResponseHeaders);
        OMLog.info(TAG, "Response code required    : " + requireResponseCode);
        OMLog.info(TAG, "Response string required  : " + requireResponseString);
        if (shouldSetCookieManager()) {
            CookieHandler.setDefault(OMCookieManager.getInstance());
        }
        HttpURLConnection connection;
        if (payload == null)
            payload = "";
        final byte[] payloadBytes = payload.getBytes();
        try {
            if (url.getProtocol().equals(PROTOCOL_HTTPS)) {
                try {
                    connection = getSecureUrlConnection(url);
                } catch (GeneralSecurityException gse) {
                    // secure connection not created.
                    Log.e(TAG, gse.getMessage(), gse);
                    throw new OMMobileSecurityException(OMErrorCode.UNABLE_OPEN_SECURE_CONNECTION, gse);
                }
            } else {
                connection = getUrlConnection(url);
            }
        } catch (IOException e) {
            Log.e(TAG, e.getMessage(), e);
            throw new OMMobileSecurityException(OMErrorCode.UNABLE_OPEN_CONNECTION, e);
        }
        if (connection != null) {
            OMHTTPResponse response = new OMHTTPResponse();
            InputStream inputStream = null; //get the response
            OutputStream outputStream;//send payload
            int responseCode;
            addHeaders(connection, headers);
            connection.setDoOutput(true);
            if (!TextUtils.isEmpty(payloadType)) {
                connection.setRequestProperty(HEADER_FIELD_CONTENT, payloadType);
            }
            try {
                connection.setRequestMethod(httpMethod);
                connection.setFixedLengthStreamingMode(payload.length());
            } catch (ProtocolException e) {

                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR, e);
            }
            try {
                outputStream = connection.getOutputStream();
                outputStream.write(payloadBytes);
                responseCode = connection.getResponseCode();

                OMLog.trace(TAG, "Response code : " + responseCode);
                outputStream.close();
                if (responseCode / 100 == 2) {
                    //success
                    inputStream = connection.getInputStream();
                    response.setResponseStringOnSuccess(readInputStreamString(inputStream));
                } else {
                    inputStream = connection.getErrorStream();
                    response.setResponseStringOnFailure(readInputStreamString(inputStream));
                }
                response.setResponseCode(responseCode);
            } catch (IOException e) {
                if (e instanceof SSLHandshakeException) {
                    OMLog.error(TAG, "SSLHandshakeException");
                    OMSSLSocketFactory socketFactory = ((OMSSLSocketFactory) ((HttpsURLConnection) connection).getSSLSocketFactory());
                    if (socketFactory.isServerCertUntrusted()) {
                        //handle one way ssl;
                        OMLog.info(TAG, "Creating SSLExceptionEvent");
                        SSLExceptionEvent event = new SSLExceptionEvent(socketFactory.getUntrustedServerCertChain(), socketFactory.getAuthType());
                        throw new OMMobileSecurityException(OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER, event, e);
                    } else if (socketFactory.isClientCertRequired()) {
                        OMLog.info(TAG, "Creating CBAExceptionEvent");
                        CBAExceptionEvent event = new CBAExceptionEvent(socketFactory.getIssuers(), socketFactory.getPeerHost(), socketFactory.getPeerPort(), socketFactory.getKeyTypes());
                        throw new OMMobileSecurityException(OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER, event, e);
                    }
                }
                throw new OMMobileSecurityException(OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER, e);
            } finally {
                if (inputStream != null) {
                    try {
                        inputStream.close();
                    } catch (IOException e) {
                        //Do nothing
                    }
                }
                OMLog.info(TAG, "Disconnecting...");
                connection.disconnect();
            }
            return response;
        } else {
            OMLog.error(TAG, "Unable to open the connection");
        }
        return null;
    }

    private String readInputStreamString(InputStream in) throws IOException {
        if (in != null) {
            BufferedReader responseBufferedReader = new BufferedReader(new InputStreamReader(in));
            StringBuilder responseStringBuilder;
            responseStringBuilder = new StringBuilder();
            String line;
            while ((line = responseBufferedReader.readLine()) != null) {
                responseStringBuilder.append(line);
            }
            return responseStringBuilder.toString();
        }
        return null;
    }


    private void validateURL(URL url) {
        if (url == null) {
            OMLog.error(TAG,"URL is null");
            throw new IllegalArgumentException("URL can not be null");
        }
    }

    /**
     * This returns the instance of {@link OMCertificateService} used by this
     * {@link OMConnectionHandler} instance. If SDK consumer wants to import
     * server/client certificates after initialization of
     * {@link oracle.idm.mobile.OMMobileSecurityService}, then this instance of
     * {@link OMCertificateService} should be used for the import. e.g:
     * {@link OMMobileSecurityService#getConnectionHandler()#getCertificateService()}
     * .This will make sure that SDK would use the newly imported certificates
     * for authentication.
     *
     * @return
     */
    public OMCertificateService getCertificateService() throws CertificateException {
        if (mCertificateService == null) {
            mCertificateService = new OMCertificateService(mContext);
        }
        return mCertificateService;
    }

    private OMSSLSocketFactory getSSLSocketFactory() throws GeneralSecurityException {
        if (mSocketFactory == null) {
            if (mCorrectedProtocols == null) {
                mSocketFactory = new OMSSLSocketFactory(getCertificateService(), mHandleClientCerts, DEFAULT_SSL_PROTOCOL);
            } else {
                mSocketFactory = new OMSSLSocketFactory(getCertificateService(), mHandleClientCerts, DEFAULT_SSL_PROTOCOL, mCorrectedProtocols);
            }
        }
        return mSocketFactory;
    }

    private HttpsURLConnection getSecureUrlConnection(URL url) throws IOException, GeneralSecurityException {
        HttpsURLConnection connection;
        connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(getSSLSocketFactory());

        // TODO commenting this for now as its not working because of the following issue.
        // https://code.google.com/p/android/issues/detail?id=52962
        //  if (BuildConfig.DEBUG) {
        //  Log.d(CLASS_NAME, "[OMConnectionHandler] added lenient hostname verifier for DEBUG mode");
        connection.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                OMLog.info(TAG, "Hostname: " + hostname + " verified");
                //very lenient policy.
                //TODO change after discussion
                return true;
            }
        });
        //        }
        updateHttpProps(connection);
        connection.setInstanceFollowRedirects(false);
        return connection;
    }

    private HttpURLConnection getUrlConnection(URL url) throws IOException {
        HttpURLConnection connection;
        connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        updateHttpProps(connection);
        return connection;
    }

    private void addHeaders(HttpURLConnection connection, Map<String, String> headers) {
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
            OMLog.info(TAG, "Added the custom headers to the client");
        }
    }

    private void updateHttpProps(HttpURLConnection connection) {
        connection.setConnectTimeout(mConnectionTimeout);
        connection.setReadTimeout(mReadTimeout);
    }

    /**
     * Gets the timeout value for the connection
     *
     * @return the connection timeout value in seconds
     * @hide
     */
    public int getConnectionTimeout() {
        return mConnectionTimeout;
    }

    /**
     * Sets the timeout value for this connection
     *
     * @param connectionTimeout the connection timeout value to set
     * @hide
     */
    public void setConnectionTimeout(int connectionTimeout) {
        mConnectionTimeout = connectionTimeout;
    }

    /**
     * Finds out whether the network is available or not.
     *
     * @return true / false
     */
    public boolean isNetworkAvailable(String host) {
        ConnectivityManager connectivityManager = (ConnectivityManager) mContext
                .getSystemService(Context.CONNECTIVITY_SERVICE);

        NetworkInfo activeNetworkInfo = connectivityManager
                .getActiveNetworkInfo();

        if (activeNetworkInfo != null && host != null) {
            try {
                URL url = new URL(host);
                HttpURLConnection connection = getUrlConnection(url);
                connection.connect();

                OMLog.debug(TAG + "_isNetworkAvailable",
                        "Connectivity status for host " + host
                                + " is true with response code as "
                                + connection.getResponseCode());
                return true;

            } catch (MalformedURLException e1) {
                OMLog.debug(TAG + "_isNetworkAvailable",
                        "Connectivity status for host " + host + " is false");
                return false;
            } catch (IOException e) {
                OMLog.debug(TAG + "_isNetworkAvailable",
                        "Connectivity status for host " + host + " is false");
                return false;
            }
        }

        OMLog.debug(TAG + "_isNetworkAvailable",
                "Connectivity status for host " + host + "is false");
        return false;
    }

    /**
     * This class represents the client certificate challenge during 2-way SSL
     * handshake. The components handling the client certificate challenge can
     * use this information.
     *
     * @hide
     */
    //TODO Move to separate file
    public static class OMClientCertChallenge {
        private Principal[] mIssuers;
        private String[] mKeyTypes;
        private Socket mSocket;

        public OMClientCertChallenge(final Socket socket, String[] keyTypes,
                                     Principal[] issuers) {
            mSocket = socket;
            mIssuers = issuers;
            mKeyTypes = keyTypes;
        }

        public String[] getKeys() {
            return mKeyTypes;
        }

        public Principal[] getIssuers() {

            return mIssuers;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("issuers = ");
            if (mIssuers != null) {
                int index = 0;
                int length = mIssuers.length;
                if (length > 0) {
                    sb.append("[");
                    while (index < length) {
                        sb.append(mIssuers[index].getName());
                        if (index == (length - 1)) {
                            sb.append("]");
                            break;
                        }
                        sb.append(",");
                        index++;
                    }
                } else {
                    sb.append("[]");
                }
            } else {
                sb.append("null");
            }
            sb.append(" ; ");
            sb.append("keys = ");
            if (mKeyTypes != null) {
                sb.append(Arrays.toString(mKeyTypes));
            } else {
                sb.append("null");
            }
            return sb.toString();
        }

        public String getHost() {
            return ((mSocket != null) ? mSocket.getInetAddress()
                    .getCanonicalHostName() : "");
        }

        public int getPort() {
            return ((mSocket != null) ? mSocket.getPort() : -1);
        }
    }

    private Map<String, List<String>> parseCookieFromResponseHeader(Map<String, List<String>> responseHeaders, URL url) {
        Map<String, List<String>> visitedUrlsCookiesMap = new HashMap();
        for (String headerKey : responseHeaders.keySet()) {
            if ((headerKey != null) && (headerKey.equalsIgnoreCase(SET_COOKIE_HEADER) || headerKey.equalsIgnoreCase(SET_COOKIE2_HEADER))) {
                List<String> cookieList = responseHeaders.get(headerKey);
                visitedUrlsCookiesMap.put(url.toString(), cookieList);
            }
        }
        return visitedUrlsCookiesMap;
    }

    public OMHTTPResponse httpPatch(URL url, final Map<String, String> headers, String payload, String payloadType, int flags) throws OMMobileSecurityException {
        validateURL(url);
        //right now its headers, we may expect other request preferences in future.
        boolean responseHeadersRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_HEADERS) != 0);
        boolean responseCodeRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_CODE) != 0);
        boolean responseStringRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_STRING) != 0);

        return executeHttpRequest(HTTP_PATCH, url, headers, payload, payloadType, responseCodeRequired, responseStringRequired, responseHeadersRequired);
    }

    public OMHTTPResponse httpDelete(URL url, final Map<String, String> headers, String payload, String payloadType, int flags) throws OMMobileSecurityException {
        validateURL(url);
        //right now its headers, we may expect other request preferences in future.
        boolean responseHeadersRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_HEADERS) != 0);
        boolean responseCodeRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_CODE) != 0);
        boolean responseStringRequired = ((flags & OMHTTPRequest.REQUIRE_RESPONSE_STRING) != 0);

        return executeHttpRequest(HTTP_DELETE, url, headers, payload, payloadType, responseCodeRequired, responseStringRequired, responseHeadersRequired);
    }

    /**
     * Method to check if default cookie manager should be set.
     * Syncing of cookies between webkit and HttpUrlConnection fails in android versions between 4.1 to 4.3
     * @return true if android version is later 4.3 version
     */
    private boolean shouldSetCookieManager() {
        boolean set = true;
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.KITKAT) {
            set = false;
        }
        return set;
    }

}
