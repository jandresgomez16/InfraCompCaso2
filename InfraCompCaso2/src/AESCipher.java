import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class AESCipher {

    public static byte[] cifrar(String text, SecretKey secretKey, String ALGORITMO) {
        byte [] cipheredText = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO);
            byte [] clearText = text.getBytes();
            String s1 = new String (clearText);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            cipheredText = cipher.doFinal(clearText);
            String s2 = new String (cipheredText);
        }
        catch (Exception e) { e.printStackTrace(); }
        return cipheredText;
    }

    public static String descifrar(byte [] cipheredText, SecretKey secretKey, String ALGORITMO) {
        String s = "";
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte [] clearText = cipher.doFinal(cipheredText);
            s = new String(clearText);
        }
        catch (Exception e) { e.printStackTrace(); }
        return s;
    }
}
