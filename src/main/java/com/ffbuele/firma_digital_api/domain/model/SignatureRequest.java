package com.ffbuele.firma_digital_api.domain.model;

import lombok.Data;

@Data
public class SignatureRequest {
    private byte[] xml;
    private byte[] p12;
    private String password;

//    public byte[] getP12() {
//        return p12;
//    }
//
//    public byte[] getXml() {
//        return xml;
//    }
//
//    public void setXml(byte[] xml) {
//        this.xml = xml;
//    }
//
//    public void setP12(byte[] p12) {
//        this.p12 = p12;
//    }
//
//    public String getPassword() {
//        return password;
//    }
//
//    public void setPassword(String password) {
//        this.password = password;
//    }
}
