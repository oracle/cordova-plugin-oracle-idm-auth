/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

/**
 * This class holds the version details and provides methods using which they
 * can be retrieved.
 * 
 *
 */
public class OMVersion
{
    private static final String OM_VERSION = "17.4.4-1.0.5";
    private static final String OM_VERSION_BANNER = "SDK for Android Applications";
    private static final String OM_VERSION_LABEL = "17.4.4-1.0.5";

    private static final String HYPHEN = " - ";
    private static final String OPEN_BRACKET = " (";
    private static final String CLOSE_BRACKET = ")";

    /**
     * Returns the version of the SDK.
     * 
     * @return Version of the SDK
     */
    public static String getVersion()
    {
        return OM_VERSION;
    }

    /**
     * Returns the version of the SDK along with the banner.
     * 
     * @return Version of the SDK along with banner
     */
    public static String getVersionWithBanner()
    {
        return OM_VERSION_BANNER + HYPHEN + OM_VERSION;
    }

    /**
     * Returns the version of the SDK along with banner and label details.
     * 
     * @return Version of the SDK along with banner and label details
     */
    public static String getVersionWithLabel()
    {
        return getVersionWithBanner() + OPEN_BRACKET + OM_VERSION_LABEL
                + CLOSE_BRACKET;
    }
}
