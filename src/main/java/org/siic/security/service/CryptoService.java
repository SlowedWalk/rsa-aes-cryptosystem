package org.siic.security.service;

import lombok.extern.slf4j.Slf4j;
import org.siic.security.utils.EncryptionUtil;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

@Service
@Slf4j
public class CryptoService {

        public Resource encryptFile(MultipartFile file, String publicKeyString) throws Exception {
            log.info("Encrypting file...");
            EncryptionUtil.encryptFile(file, publicKeyString);

            String fileExtension = Objects.requireNonNull(file.getOriginalFilename()).split("\\.")[1];
            String fileName = file.getOriginalFilename().split("\\.")[0];

            Path path = Paths.get("").resolve(fileName+"_encrypted."+fileExtension);
            log.info("Path: {}", path);
            Resource resource = new UrlResource(path.toUri());
            log.info("Encryption completed successfully.");
            return resource;

        }

        public Resource decryptFile(MultipartFile file) throws Exception {
            log.info("Decrypting file...");
            EncryptionUtil.decryptFile(file);

            String fileExtension = Objects.requireNonNull(file.getOriginalFilename()).split("\\.")[1];
            String fileName = file.getOriginalFilename().split("\\.")[0];

            Path path = Paths.get("").resolve(fileName+"_decrypted."+fileExtension);
            log.info("Path: {}", path);
            Resource resource = new UrlResource(path.toUri());
            log.info("Decryption completed successfully.");
            log.info("Resource.name: {}", resource.getFilename());
            log.info("Resource.uri: {}", resource.getURI());
            return resource;
        }

        public String encryptString(String stringToEncrypt, String publicKeyString) throws Exception {
            log.info("Encrypting file...");
            String cipherText = EncryptionUtil.encryptString(stringToEncrypt, publicKeyString);
            log.info("Encryption completed successfully.");
            return cipherText;
        }

        public String decryptString(String stringToDecrypt) throws Exception {
            log.info("Encrypting file...");
            String cipherText = EncryptionUtil.decryptString(stringToDecrypt);
            log.info("Encryption completed successfully.");
            return cipherText;
        }
}
