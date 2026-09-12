package br.com.fiap.oficina.auth.service;

public class CpfValidator {

    private static final int CPF_LENGTH = 11;

    public boolean isValid(String cpf) {
        if (cpf == null) {
            return false;
        }

        String digits = cpf.replaceAll("\\D", "");

        if (digits.length() != CPF_LENGTH || hasAllDigitsEqual(digits)) {
            return false;
        }

        int firstVerifierDigit = calculateVerifierDigit(digits, 9, 10);
        int secondVerifierDigit = calculateVerifierDigit(digits, 10, 11);

        return Character.getNumericValue(digits.charAt(9)) == firstVerifierDigit
                && Character.getNumericValue(digits.charAt(10)) == secondVerifierDigit;
    }

    private boolean hasAllDigitsEqual(String digits) {
        char firstDigit = digits.charAt(0);

        for (int i = 1; i < digits.length(); i++) {
            if (digits.charAt(i) != firstDigit) {
                return false;
            }
        }

        return true;
    }

    private int calculateVerifierDigit(String digits, int length, int initialWeight) {
        int sum = 0;

        for (int i = 0; i < length; i++) {
            sum += Character.getNumericValue(digits.charAt(i)) * (initialWeight - i);
        }

        int remainder = sum % 11;
        return remainder < 2 ? 0 : 11 - remainder;
    }
}
