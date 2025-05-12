package com.srun.login.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Md5 {

    public static String md5(String password, String token) {
        try {
            Mac hmacMd5 = Mac.getInstance("HmacMD5");
            SecretKeySpec secretKey = new SecretKeySpec(
                    token.getBytes(StandardCharsets.UTF_8),
                    "HmacMD5"
            );
            hmacMd5.init(secretKey);
            byte[] hashBytes = hmacMd5.doFinal(password.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HMAC计算失败", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
