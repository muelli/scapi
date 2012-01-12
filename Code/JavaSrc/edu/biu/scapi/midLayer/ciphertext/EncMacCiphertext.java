/**
 * 
 */
package edu.biu.scapi.midLayer.ciphertext;

/**
 * This class is a container for cipher-texts that include actual cipher data and the resulting tag.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class EncMacCiphertext extends SymmetricCiphertext {
	byte[] tag = null;
	
	public EncMacCiphertext( byte[] cipher, byte[] tag){
		super(cipher);
		this.tag = tag;
	}
	
	public EncMacCiphertext( SymmetricCiphertext cipher, byte[] tag){
		super(cipher.getCipher());
		this.tag = tag;
	}
}
