package com.etollpay.authcode.sm.provider;

import com.etollpay.authcode.sm.SmCipherProvider;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.List;

public class BcSmProvider implements SmCipherProvider {

    private static Logger log = LoggerFactory.getLogger(BcSmProvider.class);

    public static final String ALGORITHM_NAME = "SM4/CTR/NoPadding";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private ECParameterSpec ecParameterSpec;

    public BcSmProvider() {
        ecParameterSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
    }

    @Override
    public byte[] sm4Encrypt(byte[] plainText, byte[] secret) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
            Key sm4Key = new SecretKeySpec(secret, ALGORITHM_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, sm4Key, new IvParameterSpec(new byte[16]));
            return cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] sm3Digest(byte[] content) {
        Digest sm3Digest = new SM3Digest();
        byte[] hashValue = new byte[sm3Digest.getDigestSize()];
        sm3Digest.update(content, 0, content.length);
        sm3Digest.doFinal(hashValue, 0);
        return hashValue;
    }

    @Override
    public byte[] sm2Sign(byte[] content, byte[] priKey, String id) {
        try {
            ECDomainParameters ecDomainParameters = getDomainParameters();
            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(new BigInteger(1, priKey),
                    ecDomainParameters);
            ParametersWithID parameters = new ParametersWithID(privateKey, id.getBytes(StandardCharsets.UTF_8));
            SM2Signer sm2Signer = new SM2Signer();
            sm2Signer.init(true, parameters);
            sm2Signer.update(content, 0, content.length);
            return sm2Signer.generateSignature();
        } catch (CryptoException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean sm2Verify(byte[] content, byte[] signature, byte[] pubKey, String id) {
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(
                publicKeyToPoint(pubKey, 0), getDomainParameters());
        ParametersWithID parameters = new ParametersWithID(publicKey, id.getBytes(StandardCharsets.UTF_8));
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(false, parameters);
        sm2Signer.update(content, 0, content.length);
        return sm2Signer.verifySignature(signature);
    }

    @Override
    public BigInteger getSignatureR(byte[] asn1Signature) {
        return getIntFrom(asn1Signature, 0);
    }

    @Override
    public BigInteger getSignatureS(byte[] asn1Signature) {
        return getIntFrom(asn1Signature, 1);
    }

    private ECDomainParameters getDomainParameters() {
        return new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN(),
                ecParameterSpec.getH(), ecParameterSpec.getSeed());
    }

    private ECPoint asn1PubKeyToPoint(byte[] asn1Input) {
        List<DERBitString> list = BcAsn1Filter.get(asn1Input, DERBitString.class);
        if (list.size() == 0) {
            throw new RuntimeException("public key not found.");
        }
        byte[] pubKey = list.get(0).getBytes();
        if (pubKey[0] != 0x04) {
            throw new RuntimeException("only support uncompress public key.");
        }
        return publicKeyToPoint(pubKey, 1);
    }

    private ECPoint publicKeyToPoint(byte[] buff, int offset) {
        if (buff.length < offset + 64) {
            throw new RuntimeException("Invalid public key");
        }
        BigInteger x = new BigInteger(1, buff, offset, 32);
        BigInteger y = new BigInteger(1, buff, offset + 32, 32);
        return ecParameterSpec.getCurve().createPoint(x, y);
    }

    private BigInteger getIntFrom(byte[] asn1Signature, int index) {
        List<ASN1Integer> list = BcAsn1Filter.get(asn1Signature, ASN1Integer.class);
        if (list.size() > index) {
            return list.get(index).getValue();

        }
        return null;
    }

}
