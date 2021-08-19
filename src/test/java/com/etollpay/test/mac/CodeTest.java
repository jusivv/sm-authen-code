package com.etollpay.test.mac;

import com.etollpay.authcode.mac.SmMacCalculator;
import com.etollpay.authcode.signing.SmSigner;
import com.etollpay.authcode.sm.provider.BcAsn1Filter;
import com.etollpay.authcode.sm.provider.BcSmProvider;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.util.encoders.Hex;
import org.coodex.util.Common;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class CodeTest {
    private static Logger log = LoggerFactory.getLogger(CodeTest.class);

    public static void main(String[] args) throws IOException {
//        testSign();
//        testReadASN1();
//        testVerify();
        testMac();
    }

    private static void testSign() throws IOException {
        String serialNo = "10115020120210419000001";
        String hexPriKey = "1A75042AC5B609B14A6B3268BE1D2FCD41CC5261B78E69F1CE8F0D971832B1E3";
        String id = "test";

        SmSigner signer = new SmSigner(new BcSmProvider());
        byte[] signature = signer.sign(serialNo.getBytes(StandardCharsets.UTF_8),
                Hex.decode(hexPriKey), id);
        saveFile(signature, "/Users/sujiwu/Downloads/sig.der");
    }

    private static void testVerify() {
        String serialNo = "10115020120210419";
        String signature = "3045022100874156E369376C67E1AD383F2AFBEF9D17ADE029F356E6EF60F36C607283494002200DB6F946B5F655A5FAAB2C488982113432CAEB74EA04A52FA20DAA738C0B90F9";
        String pubKey = "E7C2B773E70A6AA24F16ED648A7913D5C662712E4CABB81431659D1D30D406DD09029CCCDE4324C6F11294B62FD5F9A1589DE1013ADE2A3AEA5CEE74CD0A432B";
        String id = "test";

        SmSigner signer = new SmSigner(new BcSmProvider());
        boolean result = signer.verify(serialNo.getBytes(StandardCharsets.UTF_8),
                Hex.decode(signature), Hex.decode(pubKey), id);
        log.debug("verify: {}", result ? "success": "failure");
    }

    private static void testSmMac() {
        String secret = "0123456789ABCDEF";
        String serialNo = "10115020120210419";
        SmMacCalculator macCalculator = new SmMacCalculator(new BcSmProvider());
        int mac = macCalculator.calculate(serialNo.getBytes(StandardCharsets.UTF_8),
                secret.getBytes(StandardCharsets.UTF_8), 6);
        log.debug("mac: {}", mac);
    }

    private static void testReadASN1() throws IOException {
        byte[] asn1Bytes = readFile("/Users/sujiwu/Downloads/sig.der");
        List<ASN1Integer> list = BcAsn1Filter.get(asn1Bytes, ASN1Integer.class);
        SmSigner signer = new SmSigner(new BcSmProvider());
        int mac = signer.getSMac(asn1Bytes, 6);
        log.debug("signature s mac: {}", mac);
    }

    private static byte[] readFile(String fn) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        InputStream is = new FileInputStream(fn);
        try {
            Common.copyStream(is, baos);
        } finally {
            is.close();
        }
        return baos.toByteArray();
    }

    private static void saveFile(byte[] fileContent, String fn) {
        try {
            OutputStream outputStream = new FileOutputStream(fn);
            try {
                outputStream.write(fileContent);
                outputStream.flush();
            } finally {
                outputStream.close();
            }
        } catch (FileNotFoundException e) {
            log.error(e.getLocalizedMessage(), e);
        } catch (IOException e) {
            log.error(e.getLocalizedMessage(), e);
        }
    }

    private static void testMac() {
        String secret = "0123456789ABCDEFFEDCBA9876543210";
        String serialNo = "10115020120210419";
        SmSigner signer = new SmSigner(new BcSmProvider());
        int mac = signer.getMac(serialNo.getBytes(StandardCharsets.UTF_8), secret.getBytes(StandardCharsets.UTF_8),
                6);
        log.debug("MAC: {}", mac);
        boolean ok = signer.verifyMac(serialNo.getBytes(StandardCharsets.UTF_8), mac,
                secret.getBytes(StandardCharsets.UTF_8),6);
        log.debug("Verify result: {}", ok);
    }

}
