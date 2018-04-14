import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

public class Cliente {
    //Cadenas de control
    private static final String CTO = "Connection timed out";
    private static final String SIN = "Server << ";
    private static final String SOUT = "Client >> ";
    private static final String INIC = "HOLA";
    private static final String ALG = "ALGORITMOS";
    private static final String CC = "CERTCLNT";
    private static final String CS = "CERTSRV";
    private static final String OK = "ESTADO:OK";
    private static final String ERR = "ESTADO:ERROR";
    private static final String CRTERR = "El certificado enviado no es valido";

    //Cadenas de referencia
    private static final String MD5 = "HMACMD5";
    private static final String SHA1 = "HMACSHA1";
    private static final String SHA256 = "HMACSHA256";
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String BF = "BLOWFISH";

    //Client data
    Socket socket = null;
    PrintWriter writer = null;
    BufferedReader reader = null;
    KeyPair keyPair = null;

    //User data
    BufferedReader stdIn = null;

    public void iniciar() throws IOException, CertificateException {
        stdIn = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("En que puerto esta el servidor?");
        int port = 9160;
        try {
            port = Integer.parseInt(stdIn.readLine());
        } catch (Exception e) { }

        try {
            socket = new Socket(InetAddress.getLocalHost(), port);
        } catch (Exception e) { e.printStackTrace(); System.exit(-1); }

        writer = new PrintWriter(socket.getOutputStream(), true);
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        //Iniciar protocolo con el servidor
        System.out.println("Desea iniciar la conexion? (Y/N)");
        String s = stdIn.readLine();
        if(s.equals("1") || s.equals("Y")) {
            writer.println(INIC);
            System.out.println(SOUT + INIC);
        }
        else System.exit(0);

        //Recibir respuesta servidor
        s = reader.readLine();
        if(s != null) System.out.println(SIN + s);
        else {
            System.out.println(CTO);
            System.exit(-1);
        }

        //Enviar algoritmos a usar
        String[] ALGORITMOS = preguntaAlgoritmos();
        String msg = ALG + ":" + ALGORITMOS[0] + ":RSA:" + ALGORITMOS[1];
        writer.println(msg);
        System.out.println(SOUT + msg);

        //Recibir compatibilidad de algoritmos
        s = reader.readLine();
        if(s != null) System.out.println(SIN + s);
        else {
            System.out.println(CTO);
            System.exit(-1);
        }

        //Generar certificado
        java.security.cert.X509Certificate cert = null;
        try {
            cert = generarCertificado("SHA256WithRSA");
        } catch (Exception e) { e.printStackTrace(); }
        if(cert == null) System.exit(-1);

        //Enviar certificado
        writer.println(CC);
        System.out.println(SOUT + CC);
        try {
            socket.getOutputStream().write(cert.getEncoded());
            socket.getOutputStream().flush();
            System.out.println(SOUT + "Client certificate bytes");
        } catch (Exception e) { e.printStackTrace(); }

        //Leer resultado certificado
        s = reader.readLine();
        if(s != null) {
            System.out.println(SIN + s);
        }
        else {
            System.out.println(CTO);
            System.exit(-1);
        }

        //Leer bytes del certificado
        byte[] temp = new byte[1024];
        int k = socket.getInputStream().read(temp);
        byte[] bytes = Arrays.copyOf(temp, k);
        System.out.println(SIN + "Server certificate bytes");

        //Extraer PublicKey del certificado
        InputStream is = new ByteArrayInputStream(bytes);
        X509Certificate serverCert = null;
        try {
            serverCert = (X509Certificate) (CertificateFactory.getInstance("X.509")).generateCertificate(is);
        } catch (Exception e) { writer.println(ERR); System.out.println(SOUT + ERR); System.exit(-1);}
        PublicKey publicKey = serverCert.getPublicKey();

        //Validar fecha certificado
        Date a = serverCert.getNotAfter();
        Date b = serverCert.getNotBefore();
        Date d = new Date();
        if(a.compareTo(d) * d.compareTo(b) > 0) {
            writer.println(OK);
            System.out.println(SOUT + OK);
        }
        else {
            writer.println(ERR);
            System.out.println(CRTERR);
            System.exit(-1);
        }

        //Leer mensaje encriptado
        reader.readLine();
        s = reader.readLine();
        System.out.println(SIN + s);

        //Descifrar mensaje
        s = s.split(":")[1];
        byte[] llaveBytes = RSACipher.descifrar(s.getBytes(), keyPair.getPrivate());
        SecretKey secretKey = new SecretKeySpec(llaveBytes, 0, llaveBytes.length, "RSA");


    }

    public java.security.cert.X509Certificate generarCertificado(String algorithm) throws Exception
    {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        Date notBefore = new Date();
        Date notAfter = new Date(2018, 12, 31);
        BigInteger randomSerial = new BigInteger(32,new Random());
        Security.addProvider(new BouncyCastleProvider());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new X500Name("CN=Cert"),
                randomSerial, notBefore, notAfter, new X500Name("CN=JAGV"),
                new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded())));

        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        X509CertificateHolder holder = builder.build((new BcRSAContentSignerBuilder(sigAlgId, digAlgId)).build(privateKeyAsymKeyParam));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    public String[] preguntaAlgoritmos() throws IOException {
        String[] alg = new String[2];

        System.out.println("Que algoritmo simetrico desea usar?" +
                "\n" + "(1) AES" + "\n" + "(2) Blowfish");
        if(stdIn.readLine().equals("2")) alg[0] = BF;
        else alg[0] = AES;

        System.out.println("Que algoritmo HMAC desea usar?" +
                "\n" + "(1) MD5" + "\n" + "(2) SHA1" + "\n" + "(3) SHA256");
        String s = stdIn.readLine();
        if(s.equals("2")) alg[1] = SHA1;
        else if(s.equals("3")) alg[1] = SHA256;
        else alg[1] = MD5;

        return alg;
    }

    public static void main(String[] args) {
        Cliente cliente = new Cliente();
        try {
            cliente.iniciar();
        } catch (Exception e) { e.printStackTrace(); }
    }
}
