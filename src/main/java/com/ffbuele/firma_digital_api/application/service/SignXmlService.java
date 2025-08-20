package com.ffbuele.firma_digital_api.application.service;

import com.ffbuele.firma_digital_api.domain.model.SignatureRequest;

public interface SignXmlService {
    byte[] signXml(SignatureRequest request) throws Exception;
}
