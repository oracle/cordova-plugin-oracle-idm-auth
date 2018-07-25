/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import android.webkit.CookieSyncManager;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OMCookie;
import oracle.idm.mobile.logging.OMLog;

/**
 * This makes webkit's cookie store as the cookie store of HttpUrlConnection. It also provides certain cookie related utility methods.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class OMCookieManager extends CookieManager {

    public static final String SET_COOKIE_HEADER = "Set-Cookie";
    public static final String SET_COOKIE2_HEADER = "Set-Cookie2";
    private static final String TAG = OMCookieManager.class.getSimpleName();
    private static final String COOKIE_HEADER = "Cookie";


    private static OMCookieManager mCookieManager = new OMCookieManager();

    private android.webkit.CookieManager mWebkitCookieManager;
    private boolean trackURLs;
    private Set<URI> visitedURLs;
    /**
     * The key is URL, Value is List of Set-Cookie/Set-Cookie2 header values.
     */
    private Map<String, List<String>> mVisitedUrlsCookiesMap;

    public static OMCookieManager getInstance() {
        return mCookieManager;
    }

    private OMCookieManager() {
        super(null, CookiePolicy.ACCEPT_ALL);
        this.mWebkitCookieManager = android.webkit.CookieManager.getInstance();
    }

    @Override
    public Map<String, List<String>> get(URI uri, Map<String, List<String>> requestHeaders) throws IOException {
        OMLog.trace(TAG, "INSIDE get");

        if ((uri == null) || (requestHeaders == null)) {
            return Collections.emptyMap();
        }

        if (trackURLs) {
            visitedURLs.add(uri);
        }
        Map<String, List<String>> reqHeadersWithCookies = new HashMap<>(requestHeaders);
        String url = uri.toString();
        String cookie = this.mWebkitCookieManager.getCookie(url);
        if (!TextUtils.isEmpty(cookie)) {
            reqHeadersWithCookies.put(COOKIE_HEADER, Collections.singletonList(cookie));
        }

        OMLog.debug(TAG, "REQUEST Headers:");
        if (OMSecurityConstants.DEBUG) {
            log(reqHeadersWithCookies);
        }
        return Collections.unmodifiableMap(reqHeadersWithCookies);
    }

    @Override
    public void put(URI uri, Map<String, List<String>> responseHeaders) throws IOException {
        OMLog.trace(TAG, "INSIDE put");
        OMLog.debug(TAG, "RESPONSE Headers:");

        if ((uri == null) || (responseHeaders == null)) {
            return;
        }

        if (OMSecurityConstants.DEBUG) {
            log(responseHeaders);
        }

        String url = uri.toString();
        for (String headerKey : responseHeaders.keySet()) {
            if ((headerKey == null) || !(headerKey.equalsIgnoreCase(SET_COOKIE_HEADER) || headerKey.equalsIgnoreCase(SET_COOKIE2_HEADER))) {
                continue;
            }
            List<String> newSetCookieHeaderValues = responseHeaders.get(headerKey);
            for (String headerValue : newSetCookieHeaderValues) {
                this.mWebkitCookieManager.setCookie(url, headerValue);
            }
            if (trackURLs) {
                updateSetCookieHeaderValues(url, newSetCookieHeaderValues);
            }

        }
    }

    /**
     * Updates Set-Cookie/Set-Cookie2 header values in {@link #mVisitedUrlsCookiesMap} for the
     * url passed.
     */
    private void updateSetCookieHeaderValues(String url, List<String> newSetCookieHeaderValues) {
        List<String> existingSetCookieHeaderValues = mVisitedUrlsCookiesMap.get(url);
        List<String> finalSetCookieHeaderValues;
        if (existingSetCookieHeaderValues != null) {
            finalSetCookieHeaderValues = new ArrayList<>(existingSetCookieHeaderValues);
            finalSetCookieHeaderValues.addAll(newSetCookieHeaderValues);
        } else {
            finalSetCookieHeaderValues = newSetCookieHeaderValues;
        }
        mVisitedUrlsCookiesMap.put(url, finalSetCookieHeaderValues);
    }

    /**
     * Gets the cookies for the given URL.
     *
     * @param url the URL for which the cookies are requested
     * @return the cookies as a string, using the format of the 'Cookie' HTTP request header
     */
    public String getCookie(String url) {
        return mWebkitCookieManager.getCookie(url);
    }

    /**
     * Sets a cookie for the given URL. Any existing cookie with the same host, path and name will be replaced with the new cookie.
     * The cookie being set will be ignored if it is expired.
     *
     * @param url   the URL for which the cookie is to be set
     * @param value the cookie as a string, using the format of the 'Set-Cookie' HTTP response header
     */
    public void setCookie(String url, String value) {
        mWebkitCookieManager.setCookie(url, value);
    }

    @SuppressWarnings("deprecation")
    public void removeSessionCookies(Context context) {
        CookieSyncManager.createInstance(context);
        android.webkit.CookieManager cookieMgr = android.webkit.CookieManager.getInstance();
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            cookieMgr.removeSessionCookie();
            CookieSyncManager.getInstance().sync();
        } else {
            cookieMgr.removeSessionCookies(null);
            flush(context);
        }
        OMLog.debug(TAG, "Removed session cookies");

    }

    @SuppressWarnings("deprecation")
    public void removeSessionCookies(Context context, List<OMCookie> cookieList) {
        if (cookieList == null || cookieList.isEmpty()) {
            return;
        }

        CookieSyncManager.createInstance(context);
        OMCookieManager cookieMgr = OMCookieManager.getInstance();

        for (OMCookie cookie : cookieList) {
                /*if expiryDate is set to a date in past, then it means that this cookie was already deleted as part of authentication. Hence, we can ignore it .*/
            String expiryDate = cookie.getExpiryDateStr();
            if (expiryDate != null) {
                continue;
            }
            String cookieName = cookie.getName();
            StringBuilder setCookieValue = new StringBuilder();
            setCookieValue.append(cookieName + "=");
            URL visitedURL = null;
            try {
                visitedURL = new URL(cookie.getUrl());
                OMLog.debug(TAG, "_removeSessionCookies visitedURL is " + visitedURL);
                if (cookie.getDomain() != null && !cookie.getDomain().equals(visitedURL.getHost())) {
                    /*
                     * As per RFC 2109, if the domain is not specified
                     * explicitly, it defaults to request-host. If the domain is
                     * explicitly mentioned to request-host without a preceding
                     * dot, it will create another cookie with domain explicitly
                     * as "."+request-host, instead of deleting the one with
                     * request-host as domain.
                     */
                    setCookieValue.append("; domain=" + cookie.getDomain());
                }
            } catch (MalformedURLException e) {
                OMLog.debug(TAG, "malformed url " + cookie.getUrl());
                OMLog.error(TAG, e.getMessage(), e);
            }

            if (cookie.getPath() != null) {
                setCookieValue.append("; path=" + cookie.getPath());
            }
                /*Date expiryDate = cookie.getExpiryTime();
                if (expiryDate != null) {
                    SimpleDateFormat sdf = new SimpleDateFormat(COOKIE_EXPIRY_DATE_PATTERN);
                    setCookieValue.append("; expires=" + sdf.format(expiryDate));
                }*/
            if (cookie.isHttpOnly()) {
                setCookieValue.append("; httpOnly");
            }
            if (cookie.isSecure()) {
                setCookieValue.append("; secure");
            }
            if (visitedURL != null) {
                cookieMgr.setCookie(visitedURL.toString(), setCookieValue.toString());
                OMLog.debug(TAG, "Cookie being deleted: " + setCookieValue.toString());
            } else {
                OMLog.debug(TAG, "Cookie url is null for " + cookie.getName());
            }
        }

        flush(context);
        OMLog.debug(TAG, "Removed session cookies");

    }

    /**
     * Ensures all cookies currently accessible through the getCookie API are written to persistent storage.
     * This call will block the caller until it is done and may perform I/O. This should be called from a
     * background thread, and NOT from UI thread.
     */
    @SuppressWarnings("deprecation")
    public void flush(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            mWebkitCookieManager.flush();
        } else {
            CookieSyncManager.createInstance(context);
            CookieSyncManager cookieSyncManager = CookieSyncManager.getInstance();
            cookieSyncManager.sync();
        }
    }

    /**
     * This has to be used to track the visited urls, e.g during basic authentication. Visited urls are, in turn, required to check if required cookies,
     * given by app developer, were obtained during authentication. #stopURLTracking has to be called after authentication is done.
     *
     * @see #hasRequiredCookies(Set, Set)
     * @see #stopURLTracking()
     * @see #getVisitedURLs()
     */
    public void startURLTracking() {
        trackURLs = true;
        visitedURLs = new HashSet<>();
        mVisitedUrlsCookiesMap = new HashMap<>();
    }

    /**
     * This has to be called after authentication to stop tracking visited urls.
     */
    public void stopURLTracking() {
        trackURLs = false;
    }

    /**
     * Checks if cookies corresponding to visited urls have the required cookies or not
     *
     * @param requiredCookies The cookie names in this set should be <b>all lowercase</b>.
     */
    public boolean hasRequiredCookies(Set<String> requiredCookies, Set<URI> visitedURLs) {
        if (requiredCookies == null || requiredCookies.isEmpty()) {
            return true;
        }

        Set<String> filteredCookies = new HashSet<>();
        for (URI visitedURL : visitedURLs) {
            String cookies = mWebkitCookieManager.getCookie(visitedURL.toString());
            if (TextUtils.isEmpty(cookies)) {
                continue;
            }

            for (String requiredCookie : requiredCookies) {
                if (cookies.contains(requiredCookie)) {

                    // Check if the cookie value is valid
                    String requiredCookieValue = null;
                    int beginIndex = cookies.indexOf(requiredCookie) + requiredCookie.length() + 1;
                    if (beginIndex < cookies.length()) {
                        int endIndex = cookies.indexOf(';', beginIndex);
                        if (endIndex == -1) {
                            requiredCookieValue = cookies.substring(beginIndex);
                        } else {
                            requiredCookieValue = cookies.substring(beginIndex, endIndex);
                        }
                    }
                    if (!TextUtils.isEmpty(requiredCookieValue)) {
                        filteredCookies.add(requiredCookie);
                    }

                }
            }
        }

        return requiredCookies.size() <= filteredCookies.size();
    }

    /**
     * If requiredCookies given is valid, only matching cookies are filtered and returned,
     * Else, all cookies corresponding to visitedURLs are returned.
     */
    public Map<String, OMCookie> filterCookies(Set<String> requiredCookies, Set<String> visitedURLs) {
        Map<String, OMCookie> filteredCookies = new HashMap<>();

        for (String visitedUrl : visitedURLs) {
            String host = null;
            try {
                URL url = new URL(visitedUrl);
                host = url.getHost();
            } catch (MalformedURLException e) {
                OMLog.error(TAG, e.getMessage(), e);
            }

            String cookiesOfVisitedUrl = mWebkitCookieManager.getCookie(visitedUrl);
            /* The key in this map is <cookie name>_<host>. Host and port are
             appended as there can be multiple cookies with the same name
             issued by different servers.*/
            Map<String, OMCookie> filteredCookiesOfUrl = filterCookies(cookiesOfVisitedUrl,
                    requiredCookies, host);
            if (filteredCookiesOfUrl != null) {
                filteredCookies.putAll(filteredCookiesOfUrl);
            }
        }
        return filteredCookies;
    }

    private Map<String, OMCookie> filterCookies(String cookies,
                                                Set<String> requiredCookies, String host) {

        if (TextUtils.isEmpty(cookies)) {
            return null;
        }

        Map<String, OMCookie> filteredCookies = new HashMap<>();
        ArrayList<String> cookieNames = filterCookieNames(cookies);
        String keyToBeAppendedToCookieName = "_" + host;

        /*
            If requiredCookies given is valid, only matching cookies are filtered and returned,
            Else, all cookies corresponding to visitedURLs are returned.
        */
        boolean toBeFiltered = requiredCookies != null && !requiredCookies.isEmpty();
        int beginIndex, endIndex;

        for (String cookieName : cookieNames) {
            if (!toBeFiltered
                    || (toBeFiltered && requiredCookies.contains(cookieName))) {
                beginIndex = cookies.indexOf(cookieName) + cookieName.length() + 1;
                if (beginIndex < cookies.length()) {
                    endIndex = cookies.indexOf(';', beginIndex);
                    if (endIndex > 0) {
                        filteredCookies.put(
                                cookieName + keyToBeAppendedToCookieName,
                                new OMCookie(cookieName, cookies.substring(
                                        beginIndex, endIndex), host));
                    } else {
                        filteredCookies.put(cookieName
                                + keyToBeAppendedToCookieName, new OMCookie(
                                cookieName, cookies.substring(beginIndex), host));
                    }
                } else {
                    /* This can happen if tokens end with <cookie_name>=
                     e.g: ORA_ADF_VIEW_PAGE_ID= */
                    filteredCookies.put(cookieName + keyToBeAppendedToCookieName,
                            new OMCookie(cookieName, "", host));
                }

            }
        }

        return filteredCookies;

    }

    /**
     * Returns the name of all the cookies available in the given cookie string.
     * <p>
     * <b>Note</b> This method filter out the cookie names based on the
     * {@link CookieManager} implementation
     * <p>
     * <code> cookie1=value1;cookie2=;cookie3=value3 will be filtered to
     * [cookie1,cookie2,cookie3] </code>
     *
     * @param cookieString
     * @return
     */
    private ArrayList<String> filterCookieNames(String cookieString) {
        ArrayList<String> names = new ArrayList<>();
        String[] namevalues = cookieString.split(";[\\s]*");
        if (namevalues != null) {
            for (String namevalue : namevalues) {
                int index = namevalue.indexOf('=', 0);
                if (index != -1) {
                    String name = namevalue.substring(0, index);
                    if (!TextUtils.isEmpty(name)) {
                        name = name.trim();
                        /* REMOVE ANY LEADING OR TRAILING
                         SPACES, If found in the cookie
                         name.*/
                        names.add(name);
                    }
                }
            }
        }

        return names;
    }

    public Set<URI> getVisitedURLs() {
        return visitedURLs;
    }

    public Map<String, List<String>> getVisitedUrlsCookiesMap() {
        return mVisitedUrlsCookiesMap;
    }

    private void log(Map<String, List<String>> headers) {
        for (Map.Entry<String, List<String>> requestHeaderEntry : headers.entrySet()) {
            /*Even sensitive info like Authorization header is logged as this method
            will be called only in debug mode.*/
            OMLog.trace(TAG, requestHeaderEntry.getKey() + " : " + requestHeaderEntry.getValue());
        }
    }


}
