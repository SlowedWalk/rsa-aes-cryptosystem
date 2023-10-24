package org.siic.security.controller;

import lombok.RequiredArgsConstructor;
import org.siic.security.dto.FileDto;
import org.siic.security.service.CryptoService;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileEncryptionController {
    private final CryptoService cryptoService;

    @PostMapping(path = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> encrypt(@ModelAttribute FileDto fileDto, String publicKeyString) throws Exception {
        Resource encryptFile = cryptoService.encryptFile(fileDto.file(), publicKeyString);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + encryptFile.getFilename() + "\"")
                .contentLength(encryptFile.contentLength())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(encryptFile);
    }

    @PostMapping(path = "/decrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> decrypt(@ModelAttribute FileDto fileDto) throws Exception {
        Resource decryptFile = cryptoService.decryptFile(fileDto.file());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + decryptFile.getFilename() + "\"")
                .contentLength(decryptFile.contentLength())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(decryptFile);
    }
}
