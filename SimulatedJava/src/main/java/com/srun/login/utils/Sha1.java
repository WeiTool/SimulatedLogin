package com.srun.login.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class Sha1 {

    public static String Sha1(
            String username,
            String hmd5,
            int acid,
            String clientIp,
            int n,
            int utype,
            String paramI,
            String token
    ) {
        String acidStr = String.valueOf(acid);
        String nStr = String.valueOf(n);
        String utypeStr = String.valueOf(utype);
        String[] parts = {"", username, hmd5, acidStr, clientIp, nStr, utypeStr, paramI};
        String joinedStr = String.join(token, parts);

        try {
            MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = sha1Digest.digest(joinedStr.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1算法不可用", e);
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
