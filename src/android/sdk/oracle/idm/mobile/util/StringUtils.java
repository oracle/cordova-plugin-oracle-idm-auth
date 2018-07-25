/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

import android.net.Uri;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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

    public static List<String> covertToList(String[] values,
            boolean urlDecodeValues)
    {
        List<String> valueList;
        if (urlDecodeValues)
        {
            valueList = new ArrayList<>();
            for (String value : values)
            {
                valueList.add(Uri.decode(value));
            }
        }
        else
        {
            valueList = Arrays.asList(values);
        }
        return valueList;
    }

    public static Set<String> covertToSet(String[] values,
            boolean urlDecodeValues)
    {
        Set<String> valueSet = new HashSet<>();
        if (urlDecodeValues)
        {
            for (String value : values)
            {
                valueSet.add(Uri.decode(value));
            }
        }
        else
        {
            valueSet.addAll(Arrays.asList(values));
        }
        return valueSet;
    }

    public static Map<String, String> covertToMap(String[] values,
            boolean urlDecodeValues)
    {
        Map<String, String> valueMap = new HashMap<>();
        for (String value : values)
        {
            String[] data = value.split(":");
            if (data.length == 2)
            {
                if (urlDecodeValues)
                {
                    valueMap.put(Uri.decode(data[0]), Uri.decode(data[1]));
                }
                else
                {
                    valueMap.put(data[0], data[1]);
                }
            }
        }
        return valueMap;
    }

}
