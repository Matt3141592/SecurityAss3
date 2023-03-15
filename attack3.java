import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class attack3 {
    
    static int portNo = 11338;
    static String ipAddy = "127.0.0.1";
	static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");   

    public static void main (String[] args) throws Exception{
	// Listen for connections, when client connects spin off a 
	// thread to run the protocol over that connection and go 
	// back to listening for new connections
	Socket socket = new Socket(ipAddy, portNo);

	byte[] keyBytes = new byte[16];
	Scanner sc = new Scanner(System.in);
	

	DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());
	DataInputStream inStream = new DataInputStream(socket.getInputStream());

	SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	Cipher decAEScipher = Cipher.getInstance("AES");			
	decAEScipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
	
	//generating x and g^x
	DHParameterSpec dhSpec = new DHParameterSpec(p,g);
    KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
    diffieHellmanGen.initialize(dhSpec);
    KeyPair serverPair = diffieHellmanGen.generateKeyPair();
    PrivateKey x = serverPair.getPrivate();
    PublicKey gToTheX = serverPair.getPublic();

	//sends g^x to the server
	outStream.writeInt(gToTheX.getEncoded().length); 
	outStream.write(gToTheX.getEncoded());
	//System.out.println("g^x cert: "+byteArrayToHexString(gToTheX.getEncoded()));

	//receive g^y from the server
	int publicKeyLen = inStream.readInt();
    byte[] message1 = new byte[publicKeyLen];
    inStream.read(message1);
    KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
    PublicKey gToTheY = keyfactoryDH.generatePublic(x509Spec);

	//calculate g^xy
	attack3 test = new attack3();
	test.calculateSessionKey(x, gToTheY);

	//give server's nonce and encrypt with session cipher, then send to server
	//SecureRandom gen = new SecureRandom();
	String str = sc.next();
    //int Nonce = sc.nextInt();
	byte[] NonceBytes = Base64.getDecoder().decode(str); //the server's nonce
	byte[] NonceBytesCT = test.encAESsessionCipher.doFinal(NonceBytes);
    outStream.write(NonceBytesCT);

	//receive step 4 from the server. Is encrypted with g^xy so can decrypt
	//contains Nc + 1 and Ns {{Nc+1}, Ns}
	byte[] message = new byte [32];
	inStream.read(message);
	byte[] bigMessage = test.decAESsessionCipher.doFinal(message);
	//first part of message is the encrypted Nc+1, can obtain server nonce now.b
	byte[] ncadd1 = Arrays.copyOfRange(bigMessage, 0, 16);
	byte[] ns = Arrays.copyOfRange(bigMessage, 16, 20);
	System.out.println("Here: "+new String(Base64.getEncoder().encode(ncadd1)));
	int serverNonce = new BigInteger(ns).intValue();
	//ns = BigInteger.valueOf(serverNonce+1).toByteArray();
	//have ns+1 so can xor with encypted nc+1
	//NonceBytes = BigInteger.valueOf(Nonce+1).toByteArray();
	System.out.println(byteArrayToHexString(ns));
	
	//receive the secret message and decrypt
	byte[] secret = new byte[208];
	//byte[] decsecret = test.decAESsessionCipher.doFinal(secret);
	//System.out.println(decsecret);
	
    }

	
	Socket myConnection;
	boolean debug = true;
	Cipher decAEScipher;
	Cipher encAEScipher;
	Cipher decAESsessionCipher;
	Cipher encAESsessionCipher;
	
	
	
	
	// This method sets decAESsessioncipher & encAESsessioncipher 
	private void calculateSessionKey(PrivateKey y, PublicKey gToTheX)  {
	    try {
		// Find g^xy
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
		serverKeyAgree.init(y);
		serverKeyAgree.doPhase(gToTheX, true);
		byte[] secretDH = serverKeyAgree.generateSecret();
		if (debug) System.out.println("g^xy: "+byteArrayToHexString(secretDH));
		//Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = new byte[16];
		System.arraycopy(secretDH,0,aesSecret,0,16);
		Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
		if (debug) System.out.println("Session key: "+byteArrayToHexString(aesSessionKey.getEncoded()));
		// Set up Cipher Objects
		decAESsessionCipher = Cipher.getInstance("AES");
		decAESsessionCipher.init(Cipher.DECRYPT_MODE, aesSessionKey);
		encAESsessionCipher = Cipher.getInstance("AES");
		encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey);
	    } catch (NoSuchAlgorithmException e ) {
		System.out.println(e);
	    } catch (InvalidKeyException e) {
		System.out.println(e);
	    } catch (NoSuchPaddingException e) {
		e.printStackTrace();
	    }
	}
	
	@SuppressWarnings("unused")
	public static void generateDHprams() throws NoSuchAlgorithmException, InvalidParameterSpecException {
	    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");   
	    paramGen.init(1024);   
	    //Generate the parameters   
	    AlgorithmParameters params = paramGen.generateParameters();   
	    DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);   
	    System.out.println("These are some good values to use for p & g with Diffie Hellman");
	    System.out.println("p: "+dhSpec.getP());
	    System.out.println("g: "+dhSpec.getG());
	    
	}
	
	private static String byteArrayToHexString(byte[] data) { 
	    StringBuffer buf = new StringBuffer();
	    for (int i = 0; i < data.length; i++) { 
		int halfbyte = (data[i] >>> 4) & 0x0F;
		int two_halfs = 0;
		do { 
		    if ((0 <= halfbyte) && (halfbyte <= 9)) 
			buf.append((char) ('0' + halfbyte));
		    else 
			buf.append((char) ('a' + (halfbyte - 10)));
		    halfbyte = data[i] & 0x0F;
		} while(two_halfs++ < 1);
	    } 
	    return buf.toString();
	} 
	
	private static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
		data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
				      + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	private static byte[] xorBytes (byte[] one, byte[] two) {
	if (one.length!=two.length) {
	    return null;
	} else {
	    byte[] result = new byte[one.length];
	    for(int i=0;i<one.length;i++) {
		result[i] = (byte) (one[i]^two[i]);
	    }
	    return result;
	}
    }
}
