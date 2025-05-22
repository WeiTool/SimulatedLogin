package com.srun.login.utils;

public class Base64 {
    // 自定义字符表
    private static final String CUSTOM_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
    private static final String STANDARD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    public static String customB64encode(byte[] data) {
        // 1. 标准Base64编码
        String standard = java.util.Base64.getEncoder().encodeToString(data);
        
        // 2. 替换字符表
        StringBuilder result = new StringBuilder();
        for (char c : standard.toCharArray()) {
            int index = STANDARD_ALPHA.indexOf(c);
            if (index != -1) {
                result.append(CUSTOM_ALPHA.charAt(index));
            } else {
                result.append(c); // 保留非标准字符（如=）
            }
        }
        
        return result.toString();
    }
}