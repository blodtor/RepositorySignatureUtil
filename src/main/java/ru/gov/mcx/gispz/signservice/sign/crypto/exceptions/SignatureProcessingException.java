package ru.gov.mcx.gispz.signservice.sign.crypto.exceptions;

/**
 * Ошибка при подписании
 */
public class SignatureProcessingException extends Exception {

    private static final long serialVersionUID = -8010336801761140376L;

    public SignatureProcessingException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignatureProcessingException(String message) {
        super(message);
    }

    public SignatureProcessingException(Throwable cause) {
        super(cause);
    }
}
