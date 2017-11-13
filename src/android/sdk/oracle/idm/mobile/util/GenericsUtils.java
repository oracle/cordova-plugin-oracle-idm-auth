/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @since 11.1.2.3.1
 * @hide
 */
public class GenericsUtils {
    /**
     * This method casts the list passed to List&lt;E&gt;. If any element in the
     * list given, is not a <code>elementClass</code>, then
     * IllegalArgumentException is thrown.
     *
     * @param list         List which may contain elements of different types
     * @param elementClass the expected type of element to be present in the list
     * @return a List which contains the same elements which were present in the
     * input list
     */
    public static <E> List<E> castToList(List<?> list, Class<E> elementClass) {
        List<E> output = new ArrayList<>();
        for (Object element : list) {
            if (element == null
                    || elementClass.isAssignableFrom(element.getClass())) {
                E castedElement = elementClass.cast(element);
                output.add(castedElement);
            } else {
                throw new IllegalArgumentException("Cannot cast to List<"
                        + elementClass.getSimpleName() + ">, element "
                        + element + " is not a " + elementClass.getSimpleName());
            }
        }
        return output;
    }

    /**
     * This method casts the set passed to Set&lt;E&gt;. If any element in the
     * set given, is not a <code>elementClass</code>, then
     * IllegalArgumentException is thrown.
     *
     * @param set          Set which may contain elements of different types
     * @param elementClass the expected type of element to be present in the set
     * @return a Set which contains the same elements which were present in the
     * input set
     */
    public static <E> Set<E> castToSet(Set<?> set, Class<E> elementClass) {
        Set<E> output = new HashSet<>();
        for (Object element : set) {
            if (element == null
                    || elementClass.isAssignableFrom(element.getClass())) {
                E castedElement = elementClass.cast(element);
                output.add(castedElement);
            } else {
                throw new IllegalArgumentException("Cannot cast to Set<"
                        + elementClass.getSimpleName() + ">, element "
                        + element + " is not a " + elementClass.getSimpleName());
            }
        }
        return output;
    }

    public static Set<URI> convert(Set<String> dataSet) throws URISyntaxException {
        Set<URI> convertedSet = new HashSet<URI>();
        for(String data : dataSet) {
            convertedSet.add(new URI(data));
        }
        return convertedSet;
    }
}
