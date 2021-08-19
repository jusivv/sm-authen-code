package com.etollpay.authcode.signing;

import com.etollpay.authcode.sm.SmCipherProvider;
import com.etollpay.authcode.util.ByteHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

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
        return getInt(sByte, offset, 32, cursor, digits);
    }

    private int getInt(byte[] origin, int offset, int length, int pos, int digits) {
        // get segment (use unsigned int)
        byte[] bytes = ByteHelper.loopClip(origin, offset, length, pos, 4).array();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(new byte[4], 0, 4);
        buffer.put(bytes, 0, 4);
        buffer.flip();
        long segment = buffer.getLong();
        return (int) (segment % Math.pow(10f, digits));
    }

    public int getMac(byte[] plainText, byte[] priKey, int digits) {
        if (priKey.length != 32) {
            throw new RuntimeException("invalid private key");
        }
        int j = 0;
        for (byte b : plainText) {
            j += b;
        }
        int keyOffset = j % 2 == 0 ? 0 : 16;
        // SM4 Encrypt
        byte[] cipherText = smCipherProvider.sm4Encrypt(plainText,
                Arrays.copyOfRange(priKey, keyOffset, keyOffset + 16));
        // SM3 Digest
        byte[] digest = smCipherProvider.sm3Digest(cipherText);
        // get bookmark
        int bookmark = digest[digest.length - 1] & 0xFF;
        // get cursor
        int cursor = bookmark % 32;
        return getInt(digest, 0, 32, cursor, digits);
    }

    public boolean verifyMac(byte[] plainText, int mac, byte[] priKey, int digits) {
        return mac == getMac(plainText, priKey, digits);
    }
}
