package br.com.fiap.oficina.auth.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CpfValidatorTest {

    private final CpfValidator cpfValidator = new CpfValidator();

    @Test
    void shouldAcceptValidCpfWithoutMask() {
        assertTrue(cpfValidator.isValid("12345678909"));
    }

    @Test
    void shouldAcceptValidCpfWithMask() {
        assertTrue(cpfValidator.isValid("123.456.789-09"));
    }

    @Test
    void shouldRejectCpfWithInvalidVerifierDigit() {
        assertFalse(cpfValidator.isValid("12345678900"));
    }

    @Test
    void shouldRejectCpfWithLessThanElevenDigits() {
        assertFalse(cpfValidator.isValid("1234567890"));
    }

    @Test
    void shouldRejectCpfWithAllDigitsEqual() {
        assertFalse(cpfValidator.isValid("11111111111"));
    }

    @Test
    void shouldRejectNullCpf() {
        assertFalse(cpfValidator.isValid(null));
    }

    @Test
    void shouldRejectEmptyCpf() {
        assertFalse(cpfValidator.isValid(""));
    }
}
