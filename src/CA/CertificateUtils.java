package CA;

//Θελούρας Κωνσταντίνος Παναγιώτης
//icsd12058

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;

//κλαση στη οποία θα υπάρχουν όλες οι μέθοδοι που έχουν να κάνουν με certificates και κλειδιά
public class CertificateUtils {

    private static String keystoreFile = "keyStoreFile.bin"; //ονομα αρχείου τυπου keystore
    private static String caAlias = "caAlias";               //μεταβλητές για το keystore, ονοματα,κωδικοι
    private static String newAlias = "newAlias";
    private static String pass = new String("abcdefgh");
    private static char[] password = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    char[] caPassword = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    public static final String SHA_ALGORITHM = "SHA1withRSA";

    public static void creatAppCerAndKeys() throws Exception {

        // παιρνουμε την ημερομηνία τώρα και σε 12 μήνες που θα χρηστούν για  το certificate
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();
        calendar.add(Calendar.MONTH, 12);
        Date endDate = calendar.getTime();

        //δημιουργία κλειδών για τη εφαρμογή
        KeyPair caKeys = generateRSAKeyPair();
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

        //στοιχεία certificate
        X500Principal dnName = new X500Principal("CN=CA root");
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName); // use the same
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(endDate);
        certGen.setPublicKey(caKeys.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        //selfsigned
        X509Certificate cert = certGen.generate(caKeys.getPrivate(), "BC");

        //certificate chain για να μπορέσει να μπεί το κλειδί στο keystore
        java.security.cert.Certificate[] certChain = new java.security.cert.Certificate[1];
        certChain[0] = cert;
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        //βάζουμε κωδικό στο keyStore
        keyStore.load(null, pass.toCharArray());
        //βάζουμε το Certificate στο keyStore
        keyStore.setCertificateEntry(newAlias, cert);
        //βάζουμε το private key στο keyStore
        keyStore.setKeyEntry("new", caKeys.getPrivate(), pass.toCharArray(), certChain);
        //εγγραφη του keyStore σε αρχείο
        FileOutputStream output = new FileOutputStream(keystoreFile);
        keyStore.store(output, password);

        //  cert = (X509Certificate) keyStore.getCertificate(newAlias);
        output.close();

    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static PrivateKey getCAPrivateKey() throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException, InvalidCipherTextException {

        FileInputStream input = new FileInputStream(keystoreFile);
        KeyStore getkeystore = KeyStore.getInstance(KeyStore.getDefaultType());
        getkeystore.load(input, pass.toCharArray());
        Key pKey = getkeystore.getKey("new", password);
        //System.out.println((PrivateKey) getkeystore.getKey("new", password));
        return (PrivateKey) getkeystore.getKey("new", password);

    }

    public static X509Certificate getCAcert() throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException, InvalidCipherTextException {

        FileInputStream input = new FileInputStream(keystoreFile);
        KeyStore getkeystore = KeyStore.getInstance(KeyStore.getDefaultType());
        getkeystore.load(input, pass.toCharArray());
        Key pKey = getkeystore.getKey("new", password);

        X509Certificate caCert;
        // System.out.println((X509Certificate) getkeystore.getCertificate(caAlias).getPublicKey());
        return caCert = (X509Certificate) getkeystore.getCertificate(caAlias);
        // caCert.verify(caCert.getPublicKey());

    }

    public static org.bouncycastle.pkcs.PKCS10CertificationRequest createCSR(KeyPair keys, String name, String surname, String username, String email, X509Certificate CAcert, PrivateKey CAprivateKey)
            throws Exception {
        //μέθοδος για την δημιουργία Request για να πάρει certificate

        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, username);
        x500NameBld.addRDN(BCStyle.NAME, name);
        x500NameBld.addRDN(BCStyle.SURNAME, surname);
        x500NameBld.addRDN(BCStyle.EmailAddress, email);

        X500Name subject = x500NameBld.build();
        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keys.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        return requestBuilder.build(new JcaContentSignerBuilder(SHA_ALGORITHM).setProvider("BC").build(CAprivateKey));
    }

    public static X509Certificate createCertificate(PKCS10CertificationRequest csr, X509Certificate CAcert, PrivateKey CAprivateKey) throws
            OperatorCreationException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        //δημιουργια Certificate από το request y

        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();

        X500Name subject = csr.getSubject();
        //timestamb για τον κωδικο του Certificate
        BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());

        calendar.add(Calendar.MONTH, 6);
        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_ALGORITHM).build(CAprivateKey);

        SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
        RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(pkInfo);

        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(rsaSpec);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(new X500Name("cn=PMCA"), certSerialNumber, startDate, endDate, subject, publicKey);

        org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();
        for (org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
            // process extension request
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
                Enumeration e = extensions.oids();
                while (e.hasMoreElements()) {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
                    Extension ext = extensions.getExtension(oid);
                    certBuilder.addExtension(oid, ext.isCritical(), ext.getParsedValue());
                }
            }
        }

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
    }

    public static X509Certificate readPerFile() throws FileNotFoundException, IOException, CertificateException {

        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream("cert.pem");
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        //PublicKey key = cer.getPublicKey();
        return cer;

    }

    public static void writePerFile(X509Certificate cer, String username) throws FileNotFoundException, IOException, CertificateEncodingException {
        FileWriter fileWriter = new FileWriter("Users/" + username + "/" + "cert.pem");
        PemWriter pemWriter = new PemWriter(fileWriter);
        PemObjectGenerator pemObject = new PemObject("certificate", cer.getEncoded());
        pemWriter.writeObject(pemObject);
        pemWriter.close();

    }

    public static void writeKeysToPerFile(PrivateKey prKey, PublicKey pubKey, String username) throws IOException {
        FileWriter fileWriter = new FileWriter("Users/" + username + "/" + "key.pem");
        PemWriter pemWriter = new PemWriter(fileWriter);
        PemObjectGenerator pemObject = new PemObject("publiKey", pubKey.getEncoded());
        PemObjectGenerator pemObject2 = new PemObject("privateKey", prKey.getEncoded());
        pemWriter.writeObject(pemObject);
        pemWriter.writeObject(pemObject2);
        pemWriter.close();
    }

    public static boolean checkCertificates() {
        return true;
    }
}
