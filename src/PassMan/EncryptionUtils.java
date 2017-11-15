package PassMan;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtils {

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    public static final int SALT_BYTES = 16;
    public static final int HASH_BYTES = 16;
    public static final int PBKDF2_ITERATION = 2000;
    public static final int PBKDF2_ITERATION2 = 1000;

    public static final int ITERATION_INDEX = 0;
    public static final int SALT_INDEX = 1;
    public static final int PBKDF2_INDEX = 2;

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static byte[] getsKey(String password, String username) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] sKey = pbkdf2(password.toCharArray(), username.getBytes(), PBKDF2_ITERATION, HASH_BYTES);
        //  System.out.println(bytesToHex(sKey));
        return sKey;
    }

    public static String getHashedPassword(byte[] sKey, String passwd) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] hPasswd = pbkdf2(bytesToHex(sKey).toCharArray(), passwd.getBytes(), PBKDF2_ITERATION2, HASH_BYTES);

        return bytesToHex(hPasswd);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);

        return skf.generateSecret(spec).getEncoded();

    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048, new SecureRandom());
        return kpGen.generateKeyPair();
    }

    public static String bytesToHex(byte[] bytes) {
    
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String DigitalSignature(String text, PublicKey publicKey, PrivateKey privateKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] data = text.getBytes("UTF8");
        Signature signature = Signature.getInstance("MD5WithRSA");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signatureBytes = signature.sign();

        String signatureEncoded = Base64.getEncoder().encodeToString(signatureBytes);

        signature.initVerify(publicKey);
        signature.update(data);
        return signatureEncoded;

    }

    public static String ecnrypt(String text, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipherText = cipher.doFinal(text.getBytes("UTF8"));
            String encryptedString = new String(Base64.getEncoder().encode(cipherText), "UTF-8");
            return encryptedString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedText, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] cipherText = Base64.getDecoder().decode(encryptedText.getBytes("UTF8"));
            String decryptedString = new String(cipher.doFinal(cipherText), "UTF-8");
            return decryptedString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String SHA1(String encPasswd) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        String returnS = (String) bytesToHex(md.digest(encPasswd.getBytes()));
        return returnS;
    }
}
