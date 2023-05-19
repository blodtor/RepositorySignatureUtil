package ru.gov.mcx.gispz.signservice.sign.crypto.exceptions;

/**
 * Ошибка, документ не подписан
 */
public class DocumentIsNotSignedException extends Exception {

    private static final long serialVersionUID = -4790470069490066305L;

    public DocumentIsNotSignedException() {
        super();
    }

    public DocumentIsNotSignedException(String message) {
        super(message);
    }
}
