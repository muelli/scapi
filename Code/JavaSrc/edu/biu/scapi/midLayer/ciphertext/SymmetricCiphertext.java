package edu.biu.scapi.midLayer.ciphertext;
/**
 * This class holds the basic data of a symmetric cipher-text.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class SymmetricCiphertext implements Ciphertext {

	private byte[] cipher = null;
	
	public SymmetricCiphertext(byte[] cipher){
		this.cipher = cipher;
	}
	
	public byte[] getCipher() {
		return this.cipher;
	}
	
}
