package com.etollpay.authcode.sm.provider;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class BcAsn1Filter {
    private static Logger log = LoggerFactory.getLogger(BcAsn1Filter.class);

    public static <T extends ASN1Object> List<T> get(byte[] input, Class<T> clazz) {
        ASN1InputStream asn1InputStream = new ASN1InputStream(input);
        try {
            ASN1Sequence asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();
            List<T> list = new ArrayList<>();
            for (Enumeration enumeration = asn1Sequence.getObjects(); enumeration.hasMoreElements(); ) {
                Object o = enumeration.nextElement();
                if (clazz.getName().equals(o.getClass().getName())) {
                    list.add((T) o);
                }
            }
            return list;
        } catch (IOException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new RuntimeException(e);
        }
    }
}
