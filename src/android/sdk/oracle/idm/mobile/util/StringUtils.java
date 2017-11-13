/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

import java.util.Set;

/**
 * Utility methods related to forming strings.
 *
 * @hide
 */
public class StringUtils {
    private static final String COMMA = ",";

    public static String convertToString(Set<String> set) {
        StringBuilder result = new StringBuilder();
        boolean appendComma = false;
        for (String item : set) {
                /*
                 * Have this logic to avoid having comma at the end of the
                 * string.
                 */
            if (appendComma) {
                result.append(COMMA);
            } else {
                appendComma = true;
            }
            result.append(item);
        }
        return result.toString();
    }
}
