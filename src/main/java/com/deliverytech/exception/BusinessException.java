package com.deliverytech.exception;

/**
 * Exceção personalizada para representar erros de regra de negócio na aplicação.
 * Servirá como base para exceções mais específicas.
 */
public class BusinessException extends RuntimeException {

    /**
     * Construtor que recebe a mensagem de erro.
     * @param message A mensagem descritiva do erro.
     */
    public BusinessException(String message) {
        super(message);
    }
}