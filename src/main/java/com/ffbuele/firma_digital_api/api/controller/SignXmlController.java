package com.ffbuele.firma_digital_api.api.controller;

import com.ffbuele.firma_digital_api.application.service.SignXmlService;
import com.ffbuele.firma_digital_api.domain.model.SignatureRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.*;

@RestController
@RequestMapping("/api/firma/xml")
@RequiredArgsConstructor
public class SignXmlController {
    private final SignXmlService signXmlService;

    @PostMapping(
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_XML_VALUE
    )
    public ResponseEntity<byte[]> signXml(
            @RequestPart("xml") MultipartFile xml,
            @RequestPart("p12") MultipartFile p12,
            @RequestPart("password") String password,
            @RequestPart("filename") String filename
    ) throws Exception {
        SignatureRequest req = new SignatureRequest();
        req.setXml(xml.getBytes());
        req.setP12(p12.getBytes());
        req.setPassword(password);

        byte[] signedXml = signXmlService.signXml(req);

        // Prepara la respuesta para que el navegador/cliente lo descargue como archivo
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=" + filename + ".xml")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(signedXml);
    }
}
