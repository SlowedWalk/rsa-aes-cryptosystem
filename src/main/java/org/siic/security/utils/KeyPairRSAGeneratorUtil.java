package org.siic.security.utils;

import lombok.extern.slf4j.Slf4j;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

@Slf4j
public class KeyPairRSAGeneratorUtil {
    private final static String DIRECTORY = System.getProperty("user.dir");

    public static void createKeys() throws NoSuchAlgorithmException, IOException {
        log.info("DIRECTORY: {}", DIRECTORY);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        try (FileOutputStream outPrivate = new FileOutputStream(DIRECTORY+ "\\src\\main\\resources" + "/private.priv")) {
            outPrivate.write(privateKey.getEncoded());
        }

        try (FileOutputStream outPublic = new FileOutputStream(DIRECTORY+ "\\src\\main\\resources" + "/public.pub")) {
            outPublic.write(publicKey.getEncoded());
        }

        log.info("Private key: {}", privateKey.getFormat());
        // prints "Private key format: PKCS#8" on my machine

        log.info("Public key: {}", publicKey.getFormat());
        // prints "Public key format: X.509" on my machine
    }
}