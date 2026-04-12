package com.example.misogi.client;

/**
 * Unchecked exception thrown when a Misogi gRPC operation fails.
 *
 * <p>Wraps underlying gRPC {@code StatusRuntimeException} or I/O errors
 * into a domain-specific exception so callers can catch a single type.</p>
 *
 * @param message human-readable description of the failure
 * @param cause   the original throwable (may be {@code null})
 */
public record MisogiException(String message, Throwable cause) extends RuntimeException {

    public MisogiException {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }
    }

    public MisogiException(String message) {
        this(message, null);
    }

    public MisogiException(String message, Throwable cause) {
        super(message, cause);
    }
}
