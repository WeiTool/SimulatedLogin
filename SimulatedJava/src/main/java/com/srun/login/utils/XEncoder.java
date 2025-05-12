package com.srun.login.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class XEncoder {

    public static List<Integer> mix(byte[] buffer, boolean appendSize) {
        List<Integer> res = new ArrayList<>();
        int index = 0;
        while (index < buffer.length) {
            byte[] chunk = new byte[4];
            Arrays.fill(chunk, (byte) 0);
            int bytesToCopy = Math.min(buffer.length - index, 4);
            System.arraycopy(buffer, index, chunk, 0, bytesToCopy);
            ByteBuffer bb = ByteBuffer.wrap(chunk).order(ByteOrder.LITTLE_ENDIAN);
            res.add(bb.getInt());
            index += 4;
        }
        if (appendSize) {
            res.add(buffer.length);
        }
        return res;
    }

    public static byte[] splite(List<Integer> buffer, boolean includeSize) {
        if (buffer.isEmpty()) {
            return new byte[0];
        }
        int sizeRecord = 0;
        if (includeSize) {
            sizeRecord = buffer.get(buffer.size() - 1);
            buffer = buffer.subList(0, buffer.size() - 1);
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(buffer.size() * 4).order(ByteOrder.LITTLE_ENDIAN);
        for (int val : buffer) {
            byteBuffer.putInt(val);
        }
        byte[] result = byteBuffer.array();
        if (includeSize) {
            byte[] trimmed = new byte[sizeRecord];
            System.arraycopy(result, 0, trimmed, 0, sizeRecord);
            return trimmed;
        }
        return result;
    }

    public static byte[] xEncode(String msg, String key) {
        if (msg == null || msg.isEmpty()) {
            return new byte[0];
        }
        List<Integer> msgU32 = mix(msg.getBytes(StandardCharsets.UTF_8), true);
        List<Integer> keyU32 = mix(key.getBytes(StandardCharsets.UTF_8), false);
        while (keyU32.size() < 4) {
            keyU32.add(0);
        }
        int lenMsg = msgU32.size();
        int last = lenMsg - 1;
        long right = msgU32.get(last) & 0xFFFFFFFFL;
        long c = 0x9E3779B9L;
        long d = 0;
        int count = 6 + 52 / lenMsg;

        for (int i = 0; i < count; i++) {
            d = (d + c) & 0xFFFFFFFFL;
            long e = (d >>> 2) & 3;
            for (int p = 0; p < lenMsg; p++) {
                long left = msgU32.get((p + 1) % lenMsg) & 0xFFFFFFFFL;
                right = (
                        (
                                ((right >>> 5) ^ (left << 2)) +
                                        (((left >>> 3) ^ (right << 4)) ^ (d ^ left)) +
                                        (keyU32.get((p & 3) ^ (int) e) ^ right) +
                                        msgU32.get(p)
                        )
                ) & 0xFFFFFFFFL;
                msgU32.set(p, (int) (right & 0xFFFFFFFFL));
            }
        }

        return splite(msgU32, false);
    }
}