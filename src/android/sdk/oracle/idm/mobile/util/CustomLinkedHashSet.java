/*
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

package oracle.idm.mobile.util;

import java.util.LinkedHashSet;

/**
 * This provides an additional functionality of providing the last element which was
 * inserted.
 */

public class CustomLinkedHashSet<E> extends LinkedHashSet<E> {

    private E lastElement;

    @Override
    public boolean add(E o) {
        lastElement = o;
        return super.add(o);
    }

    /**
     * Returns the last element which was inserted.
     */
    public E getLastElement() {
        return lastElement;
    }
}
