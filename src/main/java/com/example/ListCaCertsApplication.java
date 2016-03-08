package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication
public class ListCaCertsApplication {

    public static void main(String[] args) {
        SpringApplication.run(ListCaCertsApplication.class, args);
    }

}

@Controller
class HomeController {

    private static final String LINE = "------------------------------------------\n";

    @RequestMapping(value = "/", produces = "text/plain")
    @ResponseBody
    public String home(@RequestParam(name = "format", defaultValue = "short") String format) throws Exception {

        CertificateUtility certUtil = CertificateUtility.configureCertificateUtility().setShortFormat();

        if ("long".equals(format)) certUtil.setLongFormat();

        StringBuffer sb = new StringBuffer();
        sb.append("Keystore: ");
        sb.append(certUtil.getKeystoreFilename());
        sb.append("\n");
        sb.append(LINE);

        // Could use Java8 here
        List<String> certificates = certUtil.getCertificateAuthorities();
        certificates
                .stream()
                .forEach(s -> { sb.append(s).append(LINE); });

        System.out.println(sb);
        return sb.toString();
    }

}

/**
 *
 * CertificateUtility class is a helpful utility to extract CertificateAuthority information
 * from trusted keystores.
 *
 */
class CertificateUtility {

    private PKIXParameters parameters;
    private boolean issuer_dn = true;
    private boolean issuer_unique_name = false;
    private boolean subject_dn = true;
    private boolean subject_unique_name = false;
    private boolean not_after = false;
    private boolean not_before = false;
    private boolean issuer_san = false;
    private boolean san = false;

    private String keystoreFilename;

    private CertificateUtility(String keystoreFilename, PKIXParameters parameters) {
        this.keystoreFilename = keystoreFilename;
        this.parameters = parameters;
    }

    public static CertificateUtility configureCertificateUtility() throws NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, KeyStoreException, IOException {
        String keystoreFilename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        return configureCertificateUtility(keystoreFilename);
    }

    public static CertificateUtility configureCertificateUtility(String keystoreFilename) throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return CertificateUtility.configureCertificateUtilityWithPassword(keystoreFilename, "changeit");
    }

    public static CertificateUtility configureCertificateUtilityWithPassword(String keystoreFilename, String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        try (FileInputStream fis = new FileInputStream(keystoreFilename)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, password.toCharArray());
            PKIXParameters parameters = new PKIXParameters(keystore);
            return new CertificateUtility(keystoreFilename,parameters);
        }
    }

    public String getKeystoreFilename() {
        return keystoreFilename;
    }

    public void setKeystoreFilename(String keystoreFilename) {
        this.keystoreFilename = keystoreFilename;
    }

    public CertificateUtility setIssuerDn(boolean issuer_dn) {
        this.issuer_dn = issuer_dn;
        return this;
    }

    public CertificateUtility setIssuerUniqueName(boolean issuer_unique_name) {
        this.issuer_unique_name = issuer_unique_name;
        return this;
    }

    public CertificateUtility setSubjectDn(boolean subject_dn) {
        this.subject_dn = subject_dn;
        return this;
    }

    public CertificateUtility setSubjectUniqueName(boolean subject_unique_name) {
        this.subject_unique_name = subject_unique_name;
        return this;
    }

    public CertificateUtility setNotAfter(boolean not_after) {
        this.not_after = not_after;
        return this;
    }

    public CertificateUtility setNotBefore(boolean not_before) {
        this.not_before = not_before;
        return this;
    }

    public CertificateUtility setIssuerSan(boolean issuer_san) {
        this.issuer_san = issuer_san;
        return this;
    }

    public CertificateUtility setSan(boolean san) {
        this.san = san;
        return this;
    }

    public CertificateUtility setShortFormat() {
        this.issuer_dn = true;
        this.subject_dn = true;
        this.issuer_unique_name = false;
        this.subject_unique_name = false;
        this.issuer_san = false;
        this.san = false;
        this.not_after = false;
        this.not_before = false;
        return this;
    }

    public CertificateUtility setLongFormat() {
        this.issuer_dn = true;
        this.subject_dn = true;
        this.issuer_unique_name = true;
        this.subject_unique_name = true;
        this.issuer_san = true;
        this.san = true;
        this.not_after = true;
        this.not_before = true;
        return this;
    }

    public List<String> getCertificateAuthorities() {
        // get information for each CA
        List<String> certificates =
                parameters
                        .getTrustAnchors()
                        .stream()
                        .map(ta -> getCertificateInformation(ta.getTrustedCert()))
                        .collect(Collectors.toList());
        return certificates;
    }

    public String getCertificateInformation(X509Certificate certificate) {
        StringBuffer sb = new StringBuffer();
        if (issuer_dn)
            sb.append("  Issuer DN:            ").append(certificate.getIssuerDN()).append('\n');
        if (issuer_unique_name)
            sb.append("  Issuer Unique Name:   ").append(String.format("%02X", certificate.getIssuerUniqueID())).append('\n');
        if (subject_dn)
            sb.append("  Subject DN:           ").append(certificate.getSubjectDN()).append('\n');
        if (subject_unique_name)
            sb.append("  Subject Unique Name:  ").append(String.format("%02X", certificate.getSubjectUniqueID())).append('\n');
        if (not_after)
            sb.append("  Not After:            ").append(certificate.getNotAfter()).append('\n');
        if (not_before)
            sb.append("  Not Before:           ").append(certificate.getNotBefore()).append('\n');
        try {
            if (issuer_san)
                sb.append("  Issuer SAN:           ").append(certificate.getIssuerAlternativeNames()).append('\n');
            if (san)
                sb.append("  SAN:                  ").append(certificate.getSubjectAlternativeNames()).append('\n');
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }

}
