package com.etollpay.authcode.signing;

import com.etollpay.authcode.sm.SmCipherProvider;
import com.etollpay.authcode.util.ByteHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class SmSigner {
    private static Logger log = LoggerFactory.getLogger(SmSigner.class);

    private SmCipherProvider smCipherProvider;

    public SmSigner(SmCipherProvider smCipherProvider) {
        this.smCipherProvider = smCipherProvider;
    }

    public byte[] sign(byte[] plainText, byte[] priKey, String id) {
        return smCipherProvider.sm2Sign(plainText, priKey, id);
    }

    public boolean verify(byte[] plainText, byte[] signature, byte[] pubKey, String id) {
        return smCipherProvider.sm2Verify(plainText, signature, pubKey, id);
    }

    public int getSMac(byte[] asn1Signature, int digits) {
        BigInteger s = smCipherProvider.getSignatureS(asn1Signature);
        byte[] sByte = s.toByteArray();
        if (sByte.length < 32) {
            throw new RuntimeException("invalid s in signature");
        }
        int offset = sByte.length == 32 ? 0 : 1;
        int cursor = sByte[offset + 31] & 0xFF;
        cursor = cursor % 32;
        byte[] bytes = ByteHelper.loopClip(sByte, offset, 32, cursor, 4).array();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(new byte[4], 0, 4);
        buffer.put(bytes, 0, 4);
        buffer.flip();
        long segment = buffer.getLong();
//        log.debug("segment in bytes: {}, number: {}", Common.byte2hex(bytes).toUpperCase(), segment);
        // get mac
        return (int) (segment % Math.pow(10f, digits));
    }
}
