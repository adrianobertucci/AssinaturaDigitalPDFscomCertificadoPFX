
package com.mycompany.assinaturadigmavennetbeans;
import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.SignatureUtil;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

/**
 *
 * @author adrianobertucci
 */
public class AssinaturaDigMavenNetBeans {
// <editor-fold desc="Registro na classe o provider do BouncyCastle, usado para assinar o documento">  
        static {
        // Adicionar o provedor Bouncy Castle
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
// </editor-fold>


    public static void main(String[] args) throws Exception 
    {
        String pathApp = "/Users/adrianobertucci/Documents/Projetos/Nuclearis/DemoAssinaturaDigital/AssinaturaDigMavenNetBeans/src/main/java/com/mycompany/assinaturadigmavennetbeans/";
        String Password = "asds1312312"
      try 
      {
// <editor-fold desc="Carrega o certificado .PFX para assinatura do arquivo PDF">  
            // Caminhos dos arquivos e senha do certificado
            String keystorePath = pathApp + "certificado.pfx";
            String originalPdf = pathApp + "LaudoMedico.pdf";
            String signedPdf = pathApp +  "LaudoMedico_assinado_" + UUID.randomUUID().toString() + ".pdf";
            char[] password = "konia@1305".toCharArray();

            // Carregar o certificado PFX
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keystorePath), password);
            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, password);
            Certificate[] chain = ks.getCertificateChain(alias);
            
            //Pegando dados do certificado
            X509Certificate cert = (X509Certificate) chain[0];
            String name = cert.getSubjectX500Principal().getName();
            String PublicK = cert.getSerialNumber().toString();
// </editor-fold>              
            
// <editor-fold desc="Busca através do IP a localização">           
            //Pegar o IP
            String location="";
            try 
            {
                    URL url = new URL("https://api.ipify.org");
                    BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
                    String ipAddress = in.readLine();
                    
                    //Pelo IP buscando localização 
                    URL url2 = new URL("http://ip-api.com/json/" + ipAddress);
                    
                    BufferedReader in2 = new BufferedReader(new InputStreamReader(url2.openStream()));
                    location = in2.readLine();
                    
                    JSONObject jsonObject = new JSONObject(location);
                    String city = jsonObject.getString("city");
                    String region = jsonObject.getString("regionName"); // Estado ou região
                    String country = jsonObject.getString("country");
                    location = country + " - " + region + " IP: (" + ipAddress + ")";
                                                                                                
            } 
            catch (IOException e) 
            {
                    e.printStackTrace();
            }
// </editor-fold>

// <editor-fold desc="Prepara as informações para carimbar o PDF com as informações do certificado">  
            // Criar leitor e escritor PDF
            PdfReader reader = null;
            PdfWriter writer = null;
            PdfSigner signer = null;

            try 
            {
                reader = new PdfReader(originalPdf);
                writer = new PdfWriter(signedPdf);
                signer = new PdfSigner(reader, writer, new StampingProperties());

                // Configurações da aparência da assinatura
                //Rectangle rect = new Rectangle(36, 648, 200, 100);
                Rectangle rect = new Rectangle(230, 330, 300, 100);
               
                PdfSignatureAppearance appearance = signer.getSignatureAppearance();
                PdfFont font = PdfFontFactory.createFont(StandardFonts.HELVETICA);
                appearance.setLayer2Font(font);
                appearance.setLayer2FontSize(9);
                
                signer.getSignatureAppearance()
                      .setReason("Laudo validado") //Motivo da assinatura
                      .setLocation(location) //Localização
                      .setPageRect(rect)
                      .setPageNumber(1);

                // Processo de assinatura
                IExternalDigest digest = new BouncyCastleDigest();
                IExternalSignature signature = new PrivateKeySignature(pk, "SHA256", BouncyCastleProvider.PROVIDER_NAME);
                signer.signDetached(digest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
                
                writer.close();
                reader.close();
                
            }
            finally 
            {
                if (signer != null) 
                {
                    // Fechar o PdfSigner manualmente
                }
                if (writer != null) 
                {
                    writer.close();
                }
                if (reader != null) 
                {
                    reader.close();
                }
            }
// </editor-fold>

try {
            PdfDocument pdfDoc = new PdfDocument(new PdfReader(signedPdf));
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            List<String> signatureNames = signUtil.getSignatureNames();

            for (String signatureName : signatureNames) {
                System.out.println("Signature: " + signatureName);

                PdfPKCS7 pkcs7 = signUtil.verifySignature(signatureName);
                System.out.println("Subject: " + pkcs7.getSigningCertificate().getSubjectDN());
                System.out.println("Issuer: " + pkcs7.getSigningCertificate().getIssuerDN());
                System.out.println("Signature valid: " + pkcs7.verifySignatureIntegrityAndAuthenticity());
            }

            pdfDoc.close();
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }

      } 
      catch (Exception e) 
      {
            e.printStackTrace();
      }
    }
}
