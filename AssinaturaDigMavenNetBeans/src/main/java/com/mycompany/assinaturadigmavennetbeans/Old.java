/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license


package com.mycompany.assinaturadigmavennetbeans;



import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 *
 * @author adrianobertucci

public class AssinaturaDigMavenNetBeans {

    public static void main(String[] args) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, Exception {
        System.out.println("Hello World!");
        String pathApp = "/Users/adrianobertucci/Documents/Projetos/Nuclearis/DemoAssinaturaDigital/AssinaturaDigMavenNetBeans/src/main/java/com/mycompany/assinaturadigmavennetbeans/";
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream(pathApp + "certificado.pfx");
        ks.load(fis, "konia@1305".toCharArray());
        String alias = ks.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "konia@1305".toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        
        //Carregar PDF
        String pdfFilePath = pathApp + "LaudoMedico.pdf";
        File file = new File(pdfFilePath);
        PDDocument doc = Loader.loadPDF(file);
        //PDDocument doc = PDDocument.load(new File("caminho/para/documento.pdf"));
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("NOME");
        signature.setLocation("Localização");
        signature.setReason("Razão para assinar");
        // Data da assinatura
        signature.setSignDate(Calendar.getInstance());
        // Adiciona a assinatura ao documento
        doc.addSignature(signature);

        // Assina o PDF
        ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(new FileOutputStream(pathApp + "LaudoMedico_assinado.pdf"));
        byte[] cmsSignature = assinarDados(externalSigning.getContent(), chain, privateKey);
        externalSigning.setSignature(cmsSignature);
        doc.close();
    }
    
    public static byte[] assinarDados(InputStream content, Certificate[] chain, PrivateKey privateKey) throws Exception {
        CMSTypedData inputData = new CMSTypedData() {
        @Override
        public Object getContent() {
            return content;
        }

        @Override
        public void write(OutputStream out) throws IOException {
            // Assegura que o stream será fechado independentemente do sucesso ou falha
            try (InputStream stream = content) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = stream.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }
            }
        }

            @Override
            public ASN1ObjectIdentifier getContentType() {
                throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
            }
    };

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
    generator.addSignerInfoGenerator(
        new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().build()
        ).build(sha1Signer, (X509Certificate) chain[0])
    );

    List<Certificate> certList = new ArrayList<>();
    for (Certificate cert : chain) {
        certList.add(cert);
    }
    JcaCertStore certs = new JcaCertStore(certList);
    generator.addCertificates(certs);

    CMSSignedData signedData = generator.generate(inputData, false);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(signedData.getEncoded());
    return baos.toByteArray();
        
        
        
     
    } 
}
 */