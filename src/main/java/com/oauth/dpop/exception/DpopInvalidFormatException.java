package com.oauth.dpop.exception;

/**
 * Cannot parse DPoP Proof JWT or JWT in invalid format.
 */
public class DpopInvalidFormatException extends Exception {
    public DpopInvalidFormatException(String reason) {
        super(reason);
    }

    public DpopInvalidFormatException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
