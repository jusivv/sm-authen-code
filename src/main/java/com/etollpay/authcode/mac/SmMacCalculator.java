package com.etollpay.authcode.mac;

import com.etollpay.authcode.sm.SmCipherProvider;
import com.etollpay.authcode.util.ByteHelper;
import org.coodex.util.Common;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

public class SmMacCalculator {

    private static Logger log = LoggerFactory.getLogger(SmMacCalculator.class);

    private SmCipherProvider smCipherProvider;

    public SmMacCalculator(SmCipherProvider smCipherProvider) {
        this.smCipherProvider = smCipherProvider;
    }

    public int calculate(byte[] plainText, byte[] secret, int digits) {
        // SM4 Encrypt
        byte[] cipherText = smCipherProvider.sm4Encrypt(plainText, secret);
        log.debug("SM4 encrypt: {}", Common.byte2hex(cipherText).toUpperCase());
        // SM3 Digest
        byte[] digest = smCipherProvider.sm3Digest(cipherText);
        log.debug("SM3 digest: {}", Common.byte2hex(digest).toUpperCase());
        // get bookmark
        int bookmark = digest[digest.length - 1] & 0xFF;
        log.debug("bookmark: {}", bookmark);
        // get cursor
        int cursor = bookmark % 32;
        log.debug("cursor: {}", cursor);
        // get segment (use unsigned int)
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(new byte[4], 0, 4);
        byte[] bytes = ByteHelper.loopClip(digest, 0, 32, cursor, 4).array();
        buffer.put(bytes, 0, 4);
        buffer.flip();
        long segment = buffer.getLong();
        log.debug("segment in bytes: {}, number: {}", Common.byte2hex(bytes).toUpperCase(), segment);
        // get mac
        return (int) (segment % Math.pow(10f, digits));
    }
}
