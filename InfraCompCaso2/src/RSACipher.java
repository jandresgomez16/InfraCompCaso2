import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSACipher {
    private final static String ALGORITMO = "RSA";

    public static byte[] cifrar(PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO);
            BufferedReader stdIn =
                    new BufferedReader(new InputStreamReader(System.in));
            String pwd = stdIn.readLine();
            byte [] clearText = pwd.getBytes();
            String s1 = new String (clearText);
            System.out.println("clave original: " + s1);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte [] cipheredText = cipher.doFinal(clearText);
            return cipheredText;
        }
        catch (Exception e) { e.printStackTrace(); }
        return null;
    }

    public static byte[] descifrar(byte[] cipheredText, PrivateKey privateKey) {
        byte[] bytes = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            bytes = cipher.doFinal(cipheredText);
        }
        catch (Exception e) { e.printStackTrace(); }
        return bytes;
    }
}
