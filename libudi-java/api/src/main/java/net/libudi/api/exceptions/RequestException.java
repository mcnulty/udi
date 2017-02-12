/*
 * Copyright (c) 2011-2015, UDI Contributors
 * All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package net.libudi.api.exceptions;

/**
 * Indicates an invalid request was issued to the debuggee process
 *
 * @author mcnulty
 */
public class RequestException extends UdiException {

    /** autogenerated serialVersionUID */
    private static final long serialVersionUID = 8645121091275696067L;

    /**
     * Constructor.
     *
     * @param message the detailed message
     */
    public RequestException(String message) {
        super(message);
    }

    /**
     * Constructor.
     *
     * @param cause the cause
     */
    public RequestException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructor.
     *
     * @param message the detailed message
     * @param cause the cause
     */
    public RequestException(String message, Throwable cause) {
        super(message, cause);
    }
}