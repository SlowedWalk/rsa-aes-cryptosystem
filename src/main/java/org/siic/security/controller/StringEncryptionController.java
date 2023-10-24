package org.siic.security.controller;

import lombok.RequiredArgsConstructor;
import org.siic.security.service.CryptoService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/strings")
@RequiredArgsConstructor
public class StringEncryptionController {
    private final CryptoService cryptoService;

    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestParam String stringToEncrypt, String publicKeyString) throws Exception {
        return new ResponseEntity<>(cryptoService.encryptString(stringToEncrypt, publicKeyString), HttpStatus.OK);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestParam String stringToDecrypt) throws Exception {
        return new ResponseEntity<>(cryptoService.decryptString(stringToDecrypt), HttpStatus.OK);
    }
}
