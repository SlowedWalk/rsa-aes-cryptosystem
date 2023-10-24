package org.siic.security.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

@Slf4j
public class EncryptionUtil {
    static SecretKey secretKey;

    static {
        try {
            secretKey = generateRandomKey(256);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static String getEncryptedKeyString() throws Exception {
        byte[] encryptedKey = encryptRSA(secretKey.getEncoded(), getPublicKey());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public static void decryptFile(MultipartFile file) throws Exception {

        byte[] ciphertext = file.getBytes();

        byte[] decryptedKey = decryptRSA(Base64.getDecoder().decode(getEncryptedKeyString()), getPrivateKey());
        SecretKey decodedKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");

        // Decrypt the data with AES-CBC using the decrypted key
        byte[] decryptedData = decryptAES(ciphertext, decodedKey);
        String decryptedString = new String(decryptedData);

        // Print the decrypted data
        log.info("Encrypted Data: {}",  Base64.getEncoder().encodeToString(ciphertext).substring(0, 100));
        log.info("Decrypted Key String: {}", decodedKey);

        // EXTRACT FILE EXTENSION
        String fileExtension = file.getOriginalFilename().split("\\.")[1].replace("_encrypted", "");
        String fileName = file.getOriginalFilename().split("\\.")[0];

        // write decrypted key to file
        try (FileOutputStream decryptedFos = new FileOutputStream(fileName+"_decrypted."+fileExtension)) {
            decryptedFos.write(decryptedData);
        }
    }

    public static void encryptFile(MultipartFile file, String publicKeyString) throws Exception {

        PublicKey publicKey = getPublicKeyObjet(publicKeyString);

        byte[] plaintext = file.getBytes();
        byte[] ciphertext = encryptAES(plaintext, secretKey);

        byte[] encryptedKey = encryptRSA(secretKey.getEncoded(), publicKey);
        String encryptedKeyString = Base64.getEncoder().encodeToString(encryptedKey);

        // EXTRACT FILE EXTENSION
        String fileExtension = Objects.requireNonNull(file.getOriginalFilename()).split("\\.")[1];
        String fileName = file.getOriginalFilename().split("\\.")[0];

        // write decrypted key to file
        try (FileOutputStream fos = new FileOutputStream(fileName+"_encrypted."+fileExtension)) {
            fos.write(ciphertext);
        }
    }

    private static PublicKey getPublicKeyObjet(String publicKeyString) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);

        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return publicKeyFactory.generatePublic(publicKeySpec);
    }

    private static SecretKey generateRandomKey(int keySize) throws NoSuchAlgorithmException {
        // Generate a 256-bit random key K
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize); // 256-bit key size
        return keyGenerator.generateKey();
    }

    private static byte[] encryptAES(byte[] data, SecretKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(data);

        byte[] encryptedBytes = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedBytes, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedBytes, iv.length, ciphertext.length);

        return encryptedBytes;
    }

    private static byte[] decryptAES(byte[] encryptedBytes, SecretKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(encryptedBytes, 0, iv, 0, iv.length);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = new byte[encryptedBytes.length - iv.length];
        System.arraycopy(encryptedBytes, iv.length, ciphertext, 0, ciphertext.length);

        return cipher.doFinal(ciphertext);
    }

    private static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptRSA(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    public static PublicKey getPublicKey() throws Exception {
        byte[] publicKeyBytes = EncryptionUtil.class.getResourceAsStream("/public.pub").readAllBytes();

        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return publicKeyFactory.generatePublic(publicKeySpec);
    }

    public static PrivateKey getPrivateKey() throws Exception {
        // reading from resource folder
        byte[] privateKeyBytes = Objects.requireNonNull(EncryptionUtil.class.getResourceAsStream("/private.priv")).readAllBytes();

        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        // create private key using PKCS8EncodedKeySpec
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return privateKeyFactory.generatePrivate(privateKeySpec);
    }

    public static String encryptString(String stringToEncrypt, String publicKeyString) throws Exception {
        PublicKey publicKey = getPublicKeyObjet(publicKeyString);

        byte[] plaintext = stringToEncrypt.getBytes();
        byte[] ciphertext = encryptAES(plaintext, secretKey);

        byte[] encryptedKey = encryptRSA(secretKey.getEncoded(), publicKey);
        String encryptedKeyString = Base64.getEncoder().encodeToString(encryptedKey);

        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decryptString(String stringToEncrypt) throws Exception {
        byte[] ciphertext = Base64.getDecoder().decode(stringToEncrypt.getBytes());

        byte[] decryptedKey = decryptRSA(Base64.getDecoder().decode(getEncryptedKeyString()), getPrivateKey());
        SecretKey decodedKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");

        // Decrypt the data with AES-CBC using the decrypted key
        byte[] decryptedData = decryptAES(ciphertext, decodedKey);

        return new String(decryptedData);
    }
}
