package com.srun.login.utils;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CustomB64Encoder {

    private static final String CUSTOM_BASE64_ALPHABET =
            "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

    private static final String STANDARD_BASE64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private final Map<Character, Character> translationTable = new HashMap<>();

    public CustomB64Encoder() {
        for (int i = 0; i < STANDARD_BASE64_ALPHABET.length(); i++) {
            translationTable.put(
                    STANDARD_BASE64_ALPHABET.charAt(i),
                    CUSTOM_BASE64_ALPHABET.charAt(i)
            );
        }
    }

    public String encode(byte[] data) {
        String stdB64 = Base64.getEncoder().encodeToString(data);
        StringBuilder result = new StringBuilder();
        for (char c : stdB64.toCharArray()) {
            result.append(translationTable.getOrDefault(c, c));
        }
        int paddingIndex = result.indexOf("=");
        if (paddingIndex != -1) {
            result.setLength(paddingIndex);
        }
        return result.toString();
    }
}
