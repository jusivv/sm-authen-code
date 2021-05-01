package com.etollpay.authcode.sm;

/**
 * SM Crypto Provider
 */
public interface SmCipherProvider {
    /**
     * SM4 encrypt
     * @param plainText
     * @param secret
     * @return
     */
    byte[] sm4Encrypt(byte[] plainText, byte[] secret);

    /**
     * SM3 digest
     * @param content
     * @return
     */
    byte[] sm3Digest(byte[] content);

    /**
     * SM2 sign with SM3
     * @param content
     * @param priKey    private key with ASN.1 encode (DER)
     * @param id
     * @return          signature with ASN.1 encode
     */
    byte[] sm2Sign(byte[] content, byte[] priKey, String id);

    /**
     * verify signature SM2 with SM3
     * @param content
     * @param signature signature with ASN.1 encode
     * @param pubKey    public key with ASN.1 encode (DER)
     * @param id
     * @return
     */
    boolean sm2Verify(byte[] content, byte[] signature, byte[] pubKey, String id);
}
