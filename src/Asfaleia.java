//Θελούρας Κωνσταντίνος Παναγιώτης
//icsd12058

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
import javax.swing.JPasswordField;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Asfaleia {

   

    char[] caPassword = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    static FileOutputStream fop = null;
    static FileInputStream fin = null;
    private static KeyPair usersPair;
    private static PrivateKey caPrKey;
    private static X509Certificate caCert;
    private static X509Certificate userCert;

    public static void main(String[] args) throws Exception {
        Gui g = new Gui();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        CertificateUtils.creatAppCerAndKeys();  // το έτρεξα μόνο την πρώτη φορά για να δημιουργηθούν το certificate και τα κλειδία της εφαρμογής
    }

    public static void createAcc(User user) throws Exception {              //μέθοδος για την δημιουργία του λογαριασμού του χρήστη
        usersPair = CertificateUtils.generateRSAKeyPair();                 //δημιουργία ζεύγος κλειδιών για τον χρήστη
        caPrKey = CertificateUtils.getCAPrivateKey();                     //το private key της εφαρμογης το παιρνουμε από το keystore
        caCert = CertificateUtils.getCAcert();                           //παιρνουμε το certificate της εφαρμοφης     
        //δημιουργια request για certificate  & δημιουργία certificate απο αυτό
        userCert = CertificateUtils.createCertificate(CertificateUtils.createCSR(usersPair, user.getName(), user.getSurname(), user.getUsername(), user.getEmail(), caCert, caPrKey), caCert, caPrKey);
        //γράψημο του certificate και των κλειδιων του χρήστη σε αρχεία
        CertificateUtils.writePerFile(userCert, user.getUsername());
        CertificateUtils.writeKeysToPerFile(usersPair.getPrivate(), usersPair.getPublic(), user.getUsername());
        //hashing 
        String authHash = EncryptionUtils.getHashedPassword(EncryptionUtils.getsKey(user.getMastePasswd(), user.getUsername()), user.getMastePasswd());
        writeAuthFile(authHash, user.getUsername());

    }

    public static boolean checkHash(String username, String passd) throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IOException {
        //μέθοδος για τον έλεγχο του hash κατά την είσοδο του χρήστη

        //υπολγισμός του hash
        String hash = EncryptionUtils.getHashedPassword(EncryptionUtils.getsKey(passd, username), passd);
        //authfile
        BufferedReader br = new BufferedReader(new FileReader("test.txt"));

        String line;
        String tempUsername = "";
        String tempHash = "";
        //προσπέλαση του αρχέιου για να βρεθεί το ίδιο ζευγος username,hash
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
        //εγγραφη του αρχειου authfile κατά την εγγραφή του χρήστη στην εφαρμογή
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
        //άμμεση κρυπτογράφηση του καινούτιου κωδικου με το  sKey του χρήστη
        //System.out.println(EncryptionUtils.ecnrypt(passwd, user.getSalt()));
        String encyptedPasswd = EncryptionUtils.ecnrypt(passwd, user.getSalt());
        try {
            //εισαγωγη του νέου κωδικου στο αρχείο με τους κωδικούς του χρήστη
            fop = new FileOutputStream("Users/" + user.getUsername() + "/encryptedPasswords.txt", true);
            String st = domain + "," + encyptedPasswd + "\n";
            fop.write(st.getBytes());
            fop.close();
        } catch (IOException e) {
            System.out.println("Exception ");

        }

    }

    public static void encryptPasswd(String domain, User user) {
        // System.out.println(EncryptionUtils.ecnrypt(passwd, user.getSalt()));
    }

    public static String decryptPasswd(String domain, User user) throws FileNotFoundException, IOException {
        String line;
        String tempDomain = "";
        String tempEncPasswd = "";
        //προσπελαση του αρχείου για να βρεθεί το domain που ζητήθηκε και να αποκρυπτογραφηθεί ο κωδικος του
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

    }

    public static void deletePasswd(String domain, User user) throws FileNotFoundException, IOException { //from stack overflow
        File inputFile = new File("Users/" + user.getUsername() + "/encryptedPasswords.txt");
        File tempFile = new File("Users/" + user.getUsername() + "/encryptedPasswordsTemp.txt");

        BufferedReader reader = new BufferedReader(new FileReader(inputFile));
        BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile));

        String lineToRemove = domain;
        String currentLine;
        //δημιουργήτε ένα νέο  αρχείο που θα γραφτοθν όλλες οι γραμμες του παλιού εκτόσ απτην γραμμη ποθ θέλει να διαγραψει ο χρήστης
        //η μέθοδος αυτη βρέθηκε στο stackoverflow
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
        //μηχανισμος ακεραιοτητας κωδικών χρήστη
        String line;
        String tempDomain = "";
        String tempEncPasswd = "";
        BufferedReader br = new BufferedReader(new FileReader("Users/" + user.getUsername() + "/encryptedPasswords.txt"));
        fop = new FileOutputStream("Users/" + user.getUsername() + "/encryptedSignatures.txt", true);
        //προσπέλαση του αρχείου με τους κωδικούς του χρήστη και δημιουργία της τελικής κρυπτογραφημένης υπογραφης για κάθε έναν από αυτούς
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

            String domain_digest = "<" + tempDomain + "," + EncryptionUtils.SHA1(tempEncPasswd) + ">";

            String sign = EncryptionUtils.DigitalSignature(domain_digest, CertificateUtils.getCAcert().getPublicKey(), CertificateUtils.getCAPrivateKey());

            EncryptionUtils.ecnrypt(sign, user.getSalt());
            //εγγραφή της κρυπτογραφημένης υπογραφήςστο κατάλληλο αρχείο
            fop.write(sign.getBytes());

        }

    }

}
