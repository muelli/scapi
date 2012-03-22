/**
 * 
 */
package edu.biu.scapi.tests.midLayer;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.SecretKeyGeneratorUtil;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScCTREncRandomIV;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScEncryptThenMac;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.EncThenMacKey;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.SymKeyGenParameterSpec;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.ScCbcMacPrepending;
import edu.biu.scapi.primitives.prf.AES;
import edu.biu.scapi.primitives.prf.TripleDES;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.primitives.prf.bc.BcTripleDES;
import edu.biu.scapi.tools.Factories.MacFactory;
import edu.biu.scapi.tools.Factories.SymmetricEncFactory;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class EncThenMacTest {
	
	public SymmetricEnc testWithAllConstructors(){
		
		SecretKey encKey = null;
		try {
			encKey = SecretKeyGeneratorUtil.generateKey("AES");
		} catch (NoSuchAlgorithmException e4) {
			// TODO Auto-generated catch block
			e4.printStackTrace();
		}
		
		SecretKey macKey = null;
		try {
			macKey = SecretKeyGeneratorUtil.generateKey("TripleDES");
		} catch (NoSuchAlgorithmException e4) {
			// TODO Auto-generated catch block
			e4.printStackTrace();
		}

		
		ScCTREncRandomIV enc = null;
		ScCbcMacPrepending cbcMac = null;
		try {
			//Create and initialize the PRP that is used by the encryption object.
			AES aes = new BcAES();
			aes.init(encKey);
			//Create encryption object. There's no need to initialize. (Hmmm...)
			enc = new ScCTREncRandomIV(aes);

			//Create and initialize the PRP that is used by the Mac object.
			TripleDES tripleDes = new BcTripleDES();		
			tripleDes.init(macKey);
			//Create Mac object. There is no need to initialize.
			cbcMac = new ScCbcMacPrepending(tripleDes);
		} catch (UnInitializedException e3) {
			e3.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		

		//Create the encrypt-then-mac object using initialized encryption and authentication objects. 
		//There is no need to initialize the encrypt-then-mac object. (Hmmm...)
		ScEncryptThenMac encThenMac = null;
		try {
			encThenMac = new ScEncryptThenMac(enc, cbcMac);
		} catch (UnInitializedException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
				
		return encThenMac;
		
	}
	
	public SymmetricEnc testMixedConstructorsFactories() {
		SymKeyGenParameterSpec keySpec = new SymKeyGenParameterSpec(128);
		SecretKey encKey = null;
		ScCTREncRandomIV enc = null;
		ScCbcMacPrepending cbcMac = null;
		
		//Create and init encryption object
		try {
			enc = (ScCTREncRandomIV) SymmetricEncFactory.getInstance().getObject("CTREncRandomIV(AES)");
		} catch (FactoriesException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			encKey = enc.generateKey(keySpec );
			System.out.println("Encryption key is: " + new BigInteger(encKey.getEncoded()));
		} catch (InvalidParameterSpecException e2) {
			e2.printStackTrace();
		}
		try {
			enc.init(encKey);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		//Create and init mac object
		
		try {
			//cbcMac = new ScCbcMacPrepending("TripleDES");
			cbcMac = (ScCbcMacPrepending) MacFactory.getInstance().getObject("CBCMacPrepending(TripleDES)");
		} catch (FactoriesException e2) {
			e2.printStackTrace();
		}
		
		SecretKey macKey = null;
		try {
			macKey = cbcMac.generateKey(new SymKeyGenParameterSpec(168));
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Mac key is: " + new BigInteger(macKey.getEncoded()));
		try {
			cbcMac.init(macKey);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		//EncThenMacKey encThenMacKey = new EncThenMacKey(encKey, macKey);
		
		ScEncryptThenMac encThenMac = null;
		try {
			encThenMac = new ScEncryptThenMac(enc, cbcMac);
			
		} catch (UnInitializedException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		return encThenMac;
	}

	public SymmetricEnc testOnlyFactories() {

		ScEncryptThenMac encThenMac = null;
		//Create encryption object
		try {
			encThenMac = (ScEncryptThenMac) SymmetricEncFactory.getInstance().getObject("EncryptThenMac(CTREncRandomIV(AES),CBCMacPrepending(TripleDES))");
		} catch (FactoriesException e1) {
			e1.printStackTrace();
		}
		
		BigInteger encKeyNumber = new BigInteger("-115372549327403679219960517363761598875");
		BigInteger macKeyNumber = new BigInteger("-1371019422509288449558430383322776543988730309613999151522");
		SecretKey encThenMacKey = new EncThenMacKey(new SecretKeySpec(encKeyNumber.toByteArray(), "AES"), new SecretKeySpec(macKeyNumber.toByteArray(), "TripleDES"));
		
		
		//init the encryptor with the new secret key
		try {
			encThenMac.init(encThenMacKey);
		} catch (InvalidKeyException e1) {

			e1.printStackTrace();
		}

		return encThenMac;
	}
	
	//Encrypt and decrypt for testing:
	public void doEncryptDecrypt(ScEncryptThenMac encThenMac){
		String text = "In EncThenMac: I want to encrypt this sentence. I don't know how to make it long enough. It is suppossed to be of at least one block size";
		System.out.println("the plaintext is: " + text);
		Plaintext plain = new BasicPlaintext(text.getBytes());
		SymmetricCiphertext cipher;
		try {
			SecureRandom random = new SecureRandom();
			byte[] IV = new byte[16]; 
			random.nextBytes(IV);
			cipher = encThenMac.encrypt(plain, IV);
			System.out.println("The cipher is: " + new String(cipher.getBytes()));
			BasicPlaintext revertedPlain = (BasicPlaintext) encThenMac.decrypt(cipher);
			System.out.println();
			System.out.println("The reverted string is: " + new String(revertedPlain.getText()));
		} catch (UnInitializedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args){
		
		EncThenMacTest test = new EncThenMacTest();
		ScEncryptThenMac encThenMac;
		//First, test the scheme using constructor that accepts initialized SymmetricEnc and Mac objects.
		//In order to pass initialized objects we need to create relevant secret keys and initialize them with them.
		//Since, for example, the encryption object has not been created yet, we cannot use the generateKey function of the encryption.
		//This however, makes sense, since the reason to use the constructor that passes initialized objects assumes that the objects have been previously initialized for 
		//some other activity, and they are just being reused now.
		//So, lets create the relevant keys:
		System.out.println("First, test the scheme using constructor that accepts initialized SymmetricEnc and Mac objects.");
		encThenMac = (ScEncryptThenMac) test.testWithAllConstructors();
		test.doEncryptDecrypt(encThenMac);
		
		//Secondly, test the scheme using the constructors that pass the string with the algorithm name to create
		//the underlying encryption and mac objects. But, use the constructor that passes initialized object to create
		//the encrypt-then-mac object:
		System.out.println("Secondly, test the scheme using the constructors that pass the string with the algorithm name to create");
		System.out.println("the underlying encryption and mac objects. But, use the constructor that passes initialized object to create the encrypt-then-mac object:");
		encThenMac = (ScEncryptThenMac) test.testMixedConstructorsFactories();
		test.doEncryptDecrypt(encThenMac);
		
		//Thirdly, test enc-then-mac using the constructor that gets the names of the encryption and mac as strings, 
		//and then call the init function using an authenticated key
		System.out.println("Thirdly, test enc-then-mac using the constructor that gets the names of the encryption and mac as strings");
		encThenMac = (ScEncryptThenMac) test.testOnlyFactories();
		test.doEncryptDecrypt(encThenMac);	
	}
}
