/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

import android.text.TextUtils;
import android.util.Log;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * Utility methods related to URLs.
 */
public class URLUtils {
    private static final String TAG = URLUtils.class.getSimpleName();

    public static boolean areUrlsEqual(URL currentURL, URL expectedURL) {
        try {
            URI currentURI = currentURL.toURI();
            URI expectedURI = expectedURL.toURI();
            int currentPort = currentURI.getPort();
            int expectedPort = expectedURI.getPort();
            if (currentPort == -1)
            {
                currentPort = currentURL.getDefaultPort();
            }
            if (expectedPort == -1)
            {
                expectedPort = expectedURL.getDefaultPort();
            }
            if (currentPort != expectedPort)
            {
                return false;
            }
            return areUrisEqual(currentURI, expectedURI, true);
        } catch (URISyntaxException e) {
            return false;
        }
    }

    public static boolean areUrisEqual(URI currentURI, URI expectedURI, boolean skipPortMatching)
    {
            Log.d(TAG, "currentURI = " + currentURI + "\nexpectedURI = "
                    + expectedURI);
            /*
             * URL#equals is blocking as it resolves the hostname. Hence, using
             * URI#equals().
             */
            if (currentURI.equals(expectedURI))
            {
                return true;
            }

            String currentScheme = currentURI.getScheme();
            String expectedScheme = expectedURI.getScheme();
            if (currentScheme == null || expectedScheme == null
                    || !currentScheme.equals(expectedScheme))
            {
                return false;
            }

            String currentHost = currentURI.getHost();
            String expectedHost = expectedURI.getHost();
            if (currentHost == null || expectedHost == null
                    || !currentHost.equals(expectedHost))
            {
                return false;
            }

            if (!skipPortMatching)
            {
                int currentPort = currentURI.getPort();
                int expectedPort = expectedURI.getPort();
                if (currentPort != expectedPort)
                {
                    return false;
                }
            }

            String currentPath = currentURI.getPath();
            String expectedPath = expectedURI.getPath();
            if (!(arePathsEqual(currentPath, expectedPath)))
            {
                return false;
            }

            String currentQuery = currentURI.getQuery();
            String expectedQuery = expectedURI.getQuery();
            if (!areQueriesEqual(currentQuery, expectedQuery))
            {
                return false;
            }

        return true;
    }

    private static boolean arePathsEqual(String currentPath, String expectedPath)
    {
        /*
         * Path are equal if: 1. Both are empty 2. Both are same strings, except
         * that one ends with "/" and other does not. e.g:
         * http://www.example.com and http://www.example.com/ should be
         * considered equal.
         */
        boolean currentPathNotNull = currentPath != null;
        boolean expectedPathNotNull = expectedPath != null;
        if (currentPathNotNull)
        {
            currentPath = currentPath.trim();
        }
        if (expectedPathNotNull)
        {
            expectedPath = expectedPath.trim();
        }
        boolean currentPathEmpty = TextUtils.isEmpty(currentPath);
        boolean expectedPathEmpty = TextUtils.isEmpty(expectedPath);
        if (currentPathEmpty && expectedPathEmpty)
        {
            return true;
        }

        if (currentPathNotNull)
        {
            // For few SSO based flows, the login success url gets appended
            // with cookie name values, like
            // http://example.com:1234/home;cookie=value?a=b
            // For such URLs we will consider the path till the first ';'.
            // This behavior is made similar to iOS OS behavior.
            if (currentPath.contains(";"))
            {
                currentPath = currentPath.substring(0,
                        currentPath.indexOf(';', 0));
            }
            if (!currentPath.endsWith("/"))
            {
                currentPath = currentPath + "/";
            }
        }
        if (expectedPathNotNull && !expectedPath.endsWith("/"))
        {
            expectedPath = expectedPath + "/";
        }
        return (currentPathNotNull && currentPath.equals(expectedPath));
    }

    private static boolean areQueriesEqual(String currentQuery, String expectedQuery)
    {
        /*
         * If expectedQuery ends with *, then treat it as a wild card character
         * implying zero or more characters. This is equivalent to performing
         * startsWith comparison after removing *. This is being done only for
         * Oracle APEX Corporate SSO use-case. In case of APEX application,
         * login success URL is same as loginurl appended with sessionid as a
         * query parameter.
         */
        if (expectedQuery != null && expectedQuery.endsWith("*"))
        {
            expectedQuery = expectedQuery.substring(0,
                    expectedQuery.length() - 1);
        }
        /*
         * Queries are equal if: 1. There is no expected query parameter OR 2.
         * Current query starts with expected query, i.e, the current query can
         * have additional query parameters.
         */
        return (expectedQuery == null || (currentQuery != null && currentQuery
                .startsWith(expectedQuery)));
    }
}
