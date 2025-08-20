package com.ffbuele.firma_digital_api.infrastructure.signer;

import com.ffbuele.firma_digital_api.application.service.SignXmlService;
import com.ffbuele.firma_digital_api.domain.model.SignatureRequest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.List;

import java.security.KeyStore.PasswordProtection;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import org.springframework.stereotype.Service;

@Service
public class SignXmlWithDssService implements SignXmlService {

    @Override
    public byte[] signXml(SignatureRequest request) throws Exception {
        PasswordProtection passwordProtection = new PasswordProtection(request.getPassword().toCharArray());
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new ByteArrayInputStream(request.getP12()),
                passwordProtection)) {

            List<DSSPrivateKeyEntry> privateKeys = token.getKeys();
            if (privateKeys.isEmpty()) {
                throw new Exception("No private key found in the .p12 file");
            }
            DSSPrivateKeyEntry privateKey = privateKeys.get(0);

            DSSDocument toSignDocument = new InMemoryDocument(request.getXml());

            XAdESSignatureParameters parameters = new XAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());
            parameters.setSignedInfoCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            parameters.setXadesNamespace(new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "etsi"));

            XAdESService service = new XAdESService(new CommonCertificateVerifier());

            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            try (InputStream is = signedDocument.openStream();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, read);
                }
                return baos.toByteArray();
            }
        }
    }
}
