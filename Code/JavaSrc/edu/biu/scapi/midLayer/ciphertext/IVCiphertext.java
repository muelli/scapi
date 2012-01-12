/**
 * 
 */
package edu.biu.scapi.midLayer.ciphertext;

/**
 * This class is a container for cipher-texts that include actual cipher data and the IV used.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class IVCiphertext extends SymmetricCiphertext {
	private byte[] iv = null;
	
	public IVCiphertext(byte[] cipher, byte[] iv){
		super(cipher);
		this.iv = iv;
	}
	
	public byte[] getIv(){
		return iv;
	}
}
