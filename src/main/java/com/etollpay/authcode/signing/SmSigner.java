package com.etollpay.authcode.signing;

import com.etollpay.authcode.sm.SmCipherProvider;

public class SmSigner {
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
}
