package com.etollpay.authcode.util;

import java.nio.ByteBuffer;

public class ByteHelper {
    public static ByteBuffer loopClip(byte[] origin, int offset, int length, int pos, int size) {
        ByteBuffer buffer = ByteBuffer.allocate(size);
        if (pos >= offset && pos < offset + length) {
            for (int i = 0; i < size; i++) {
                int n = pos + i;
                while (n >= offset + length) {
                    n = n - length;
                }
                buffer.put(origin[n]);
            }
            buffer.flip();
        }
        return buffer;
    }
}
