/**
 * 
 */
package edu.biu.scapi.tests.midLayer;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.DJKeyGenParameterSpec;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScDamgardJurikEnc;
import edu.biu.scapi.midLayer.ciphertext.DJCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class DJEncTest {
	public static void main(String[] args){
		ScDamgardJurikEnc enc = new ScDamgardJurikEnc();
		DJKeyGenParameterSpec params = new DJKeyGenParameterSpec(128, 40);
		KeyPair keyPair = null;
		try {
			keyPair = enc.generateKey(params);
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			enc.setKey(keyPair.getPublic(), keyPair.getPrivate());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		BigInteger plaintext = new BigInteger("2895559838");
		System.out.println("To encrypt: " + plaintext);
		DJCiphertext cipher = (DJCiphertext) enc.encrypt(new BigIntegerPlainText(plaintext));
		System.out.println("The cipher is: " + cipher.getCipher());
		
		BigIntegerPlainText reverted = null;
		try {
			reverted = (BigIntegerPlainText) enc.decrypt(cipher) ;
		} catch (KeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("The reverted number is: " + reverted.getX());

	
	
		
		String str = new String("I want to encrypt this string");
		//BigInteger plaintext = new BigInteger(str.getBytes());
		System.out.println("To encrypt: " + str);
		cipher = (DJCiphertext) enc.encrypt(new BigIntegerPlainText(str));
		System.out.println("The cipher is: " + cipher.getCipher());
		
		reverted = null;
		try {
			reverted = (BigIntegerPlainText) enc.decrypt(cipher) ;
		} catch (KeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("The reverted number is: " + reverted.getX());
		System.out.println("The reverted string is: " + new String(reverted.getX().toByteArray()));
	}
}
