package main_program;

import guis.Gui;
import main_program.EncryptionUtils;
import certificate_authority.CertificateUtils;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class PasswodManager {

    private static FileOutputStream fop = null;
    //  private  static FileInputStream fin = null;
    private static KeyPair usersPair;
    private static PrivateKey caPrKey;
    private static X509Certificate caCert;
    private static X509Certificate userCert;
    private static Gui g;

    public static void main(String[] args) throws Exception {
        g = new Gui();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static void createAcc(User user) throws Exception {
        usersPair = CertificateUtils.generateRSAKeyPair();
        caPrKey = CertificateUtils.getCAPrivateKey();
        caCert = CertificateUtils.getCAcert();

        userCert = CertificateUtils.createCertificate(CertificateUtils.createCSR(usersPair, user.getName(), user.getSurname(), user.getUsername(), user.getEmail(), caCert, caPrKey), caCert, caPrKey);
        //write user's certificate and keys in a file 
        CertificateUtils.writePerFile(userCert, user.getUsername());
        CertificateUtils.writeKeysToPerFile(usersPair.getPrivate(), usersPair.getPublic(), user.getUsername());
        //hashing 
        String authHash = EncryptionUtils.getHashedPassword(EncryptionUtils.getsKey(user.getMastePasswd(), user.getUsername()), user.getMastePasswd());
        writeAuthFile(authHash, user.getUsername());

    }

    public static boolean checkHash(String username, String passd) throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IOException {
        //this method called when user login

        String hash = EncryptionUtils.getHashedPassword(EncryptionUtils.getsKey(passd, username), passd);
        //authfile
        BufferedReader br = new BufferedReader(new FileReader("test.txt"));

        String line;
        String tempUsername = "";
        String tempHash = "";
        //check the file for the hash username match
        while ((line = br.readLine()) != null) {
            tempUsername = "";
            tempHash = "";
            boolean b = false;

            for (int i = 0; i < line.length(); i++) {

                if (!b && line.charAt(i) != ',') {

                    tempUsername = tempUsername + line.charAt(i);

                }
                if (b && line.charAt(i) != ',') {
                    tempHash = tempHash + line.charAt(i);
                }
                if (line.charAt(i) == ',') {
                    b = true;
                }

            }
            if (username.equals(tempUsername) && hash.equals(tempHash)) {
                br.close();
                return true;
            }

        }
        if (username.equals(tempUsername) && hash.equals(tempHash)) {
            br.close();
            return true;
        }
        br.close();
        return false;
    }

    public static void writeAuthFile(String authHash, String username) {

        try {
            fop = new FileOutputStream("test.txt", true);
            String st = username + "," + authHash + "\n";
            fop.write(st.getBytes());
            fop.close();
        } catch (IOException e) {
            System.out.println("Exception ");

        }
    }

    public static void newPasswd(String passwd, User user, String domain) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //encrypt with user's sKey
        //System.out.println(EncryptionUtils.ecnrypt(passwd, user.getSalt()));
        String encyptedPasswd = EncryptionUtils.ecnrypt(passwd, user.getSalt());
        try {
            //write the new password in the file 
            fop = new FileOutputStream("Users/" + user.getUsername() + "/encryptedPasswords.txt", true);
            String st = domain + "," + encyptedPasswd + "\n";
            fop.write(st.getBytes());
            fop.close();
        } catch (IOException e) {
            System.out.println("Exception ");

        }

    }

    public static String decryptPasswd(String domain, User user) throws FileNotFoundException, IOException {
        String line;
        String tempDomain = "";
        String tempEncPasswd = "";
        //parse file to find the password
        BufferedReader br = new BufferedReader(new FileReader("Users/" + user.getUsername() + "/encryptedPasswords.txt"));
        while ((line = br.readLine()) != null) {
            tempDomain = "";
            tempEncPasswd = "";
            boolean b = false;

            for (int i = 0; i < line.length(); i++) {

                if (!b && line.charAt(i) != ',') {

                    tempDomain = tempDomain + line.charAt(i);

                }
                if (b && line.charAt(i) != ',') {
                    tempEncPasswd = tempEncPasswd + line.charAt(i);
                }
                if (line.charAt(i) == ',') {
                    b = true;
                }

            }
            if (tempDomain.equals(domain)) {
                break;

            }

        }
        System.out.println(EncryptionUtils.decrypt(tempEncPasswd, user.getSalt()));
        return EncryptionUtils.decrypt(tempEncPasswd, user.getSalt());
    }

    public static void changePasswd(User user, String domain) {
        //TODO
    }

    public static void deletePasswd(String domain, User user) throws FileNotFoundException, IOException {
        File inputFile = new File("Users/" + user.getUsername() + "/encryptedPasswords.txt");
        File tempFile = new File("Users/" + user.getUsername() + "/encryptedPasswordsTemp.txt");

        BufferedReader reader = new BufferedReader(new FileReader(inputFile));
        BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));

        String currentLine;

        while ((currentLine = reader.readLine()) != null) {
            // trim newline when comparing with lineToRemove

            if (currentLine.matches(domain + ".*")) {
                continue;
            }
            writer.write(currentLine + System.getProperty("line.separator"));
        }
        writer.close();
        reader.close();
        inputFile.delete();
        boolean successful = tempFile.renameTo(inputFile);
        if (successful) {

            System.out.println("Deleted");
        }

    }

    public static void integrityMech(User user) throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException, CertificateException, UnrecoverableKeyException, NoSuchProviderException, InvalidCipherTextException {

        String line;
        String tempDomain = "";
        String tempEncPasswd = "";
        BufferedReader br = new BufferedReader(new FileReader("Users/" + user.getUsername() + "/encryptedPasswords.txt"));
        fop = new FileOutputStream("Users/" + user.getUsername() + "/encryptedSignatures.txt", true);
 
        //parse the file with the passwords and make sign for their integridy
        while ((line = br.readLine()) != null) {

            tempDomain = "";
            tempEncPasswd = "";
            boolean b = false;

            for (int i = 0; i < line.length(); i++) {

                if (!b && line.charAt(i) != ',') {

                    tempDomain = tempDomain + line.charAt(i);

                }
                if (b && line.charAt(i) != ',') {
                    tempEncPasswd = tempEncPasswd + line.charAt(i);
                }
                if (line.charAt(i) == ',') {
                    b = true;
                }

            }

            String domain_digest = "<" + tempDomain + "," + EncryptionUtils.sha1(tempEncPasswd) + ">";

            String sign = EncryptionUtils.digitalSignature(domain_digest, CertificateUtils.getCAcert().getPublicKey(), CertificateUtils.getCAPrivateKey());

            EncryptionUtils.ecnrypt(sign, user.getSalt());
            //write the signature to a file 
            fop.write(sign.getBytes());

        }

    }

}
