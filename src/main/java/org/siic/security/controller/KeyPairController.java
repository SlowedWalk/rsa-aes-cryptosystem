package org.siic.security.controller;

import lombok.RequiredArgsConstructor;
import org.siic.security.utils.EncryptionUtil;
import org.siic.security.utils.KeyPairRSAGeneratorUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

@RestController
@RequestMapping("/api/keypair")
@RequiredArgsConstructor
public class KeyPairController {

    @GetMapping("generate-keypair")
    public String generateKeyPair() throws Exception {
        KeyPairRSAGeneratorUtil.createKeys();
        return "PUBLIC KEY = " + new String(Base64.getEncoder().encode(EncryptionUtil.getPublicKey().getEncoded()));
    }
}
