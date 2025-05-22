package com.srun.login.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Encode {

    /**
     * 将字符串转换为32位无符号整数数组（小端序）
     * @param a 输入字符串
     * @param addLength 是否在数组末尾添加原始字符串长度
     * @return 32位整型列表
     */
    public static List<Long> s(String a, boolean addLength) {
        int c = a.length();
        List<Long> v = new ArrayList<>();

        // 每4个字符为一组处理
        for (int i = 0; i < c; i += 4) {
            long value = 0;
            for (int j = 0; j < 4; j++) {
                int charIndex = i + j;
                int charCode = (charIndex < c) ? a.charAt(charIndex) : 0;
                value |= (charCode & 0xFFL) << (8 * j); // 小端序编码
            }
            v.add(value & 0xFFFFFFFFL); // 限制为32位无符号
        }

        // 添加原始字符串长度
        if (addLength) {
            v.add((long) c);
        }
        return v;
    }

    /**
     * 将32位整数列表转换为二进制数据（小端序）
     * @param a 整数列表
     * @param truncate 是否根据记录的原始长度截断
     * @return 二进制字节数组
     */
    public static byte[] l(List<Long> a, boolean truncate) {
        ByteBuffer buffer = ByteBuffer.allocate(a.size() * 4);
        buffer.order(ByteOrder.LITTLE_ENDIAN); // 小端序

        // 处理长度标记
        int originalLength = 0;
        if (truncate && !a.isEmpty()) {
            originalLength = a.get(a.size() - 1).intValue();
            a = a.subList(0, a.size() - 1);
        }

        // 转换每个整数为4字节
        for (long num : a) {
            buffer.putInt((int) (num & 0xFFFFFFFFL));
        }

        // 截断处理
        byte[] result = buffer.array();
        if (truncate) {
            result = Arrays.copyOfRange(result, 0, originalLength);
        }
        return result;
    }

    /**
     * 执行加密运算（变种XXTEA算法）
     * @param str 待加密字符串
     * @param key 加密密钥
     * @return 加密后的二进制数据
     */
    public static byte[] encode(String str, String key) {
        // 1. 数据预处理
        List<Long> v = s(str, true);
        List<Long> k = s(key, false);

        // 补全密钥长度至4
        while (k.size() < 4) {
            k.add(0L);
        }

        // 2. 初始化参数
        int n = v.size() - 1;
        if (n < 0) return new byte[0]; // 空输入处理

        long z = v.get(n);
        long y = v.get(0);
        long c = 0x9E3779B9L; // 魔数常量 0x86014019 | 0x183639A0
        int q = 6 + 52 / (n + 1);
        long d = 0;

        // 3. 主加密循环
        for (int i = 0; i < q; i++) {
            d = (d + c) & 0xFFFFFFFFL;
            int e = (int) ((d >>> 2) & 3);

            for (int p = 0; p < n; p++) {
                y = v.get(p + 1);
                long m = (z >>> 5) ^ (y << 2);
                m += (y >>> 3) ^ (z << 4) ^ (d ^ y);
                m += k.get((p & 3) ^ e) ^ z;
                m &= 0xFFFFFFFFL;

                long newVal = (v.get(p) + m) & 0xFFFFFFFFL;
                v.set(p, newVal);
                z = newVal;
            }

            y = v.get(0);
            long m = (z >>> 5) ^ (y << 2);
            m += (y >>> 3) ^ (z << 4) ^ (d ^ y);
            m += k.get((n & 3) ^ e) ^ z;
            m &= 0xFFFFFFFFL;

            long newVal = (v.get(n) + m) & 0xFFFFFFFFL;
            v.set(n, newVal);
            z = newVal;
        }

        // 4. 转换为二进制数据
        return l(v, false);
    }
}