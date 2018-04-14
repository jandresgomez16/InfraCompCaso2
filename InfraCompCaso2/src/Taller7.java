import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Taller7 {
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
            long startTime = System.nanoTime();
            byte [] cipheredText = cipher.doFinal(clearText);
            long endTime = System.nanoTime();
            System.out.println("clave cifrada: " + cipheredText);
            System.out.println("Tiempo asimetrico: " +
                    (endTime - startTime));
            return cipheredText;
        }
        catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }

    public static String descifrar(byte[] cipheredText, PrivateKey privateKey) {
        String s3 = "";
        try {
            Cipher cipher = Cipher.getInstance(ALGORITMO);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte [] clearText = cipher.doFinal(cipheredText);
            s3 = new String(clearText);
            return s3;
            /*System.out.println("clave original: " + s3);*/
        }
        catch (Exception e) {
            /*System.out.println("Excepcion: " + e.getMessage());*/
        }
        return s3;
    }

    public static void main(String[] args) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO);
            generator.initialize(1024);
            KeyPair keyPair = generator.generateKeyPair();
            descifrar(cifrar(keyPair.getPublic()), keyPair.getPrivate());
        } catch (Exception e) { e.printStackTrace(); }
    }
}
