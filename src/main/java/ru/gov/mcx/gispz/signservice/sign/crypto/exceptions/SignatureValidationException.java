package ru.gov.mcx.gispz.signservice.sign.crypto.exceptions;

/**
 * Ошибка валидации подписи
 */
public class SignatureValidationException extends Exception {

    private static final long serialVersionUID = -1389448617201522045L;

    public SignatureValidationException(String message) {
        super(message);
    }

    public SignatureValidationException(Throwable cause) {
        super(cause);
    }
}
