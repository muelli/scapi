/**
 * 
 */
package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class is a container that encapsulates the cipher data resulting from applying the El Gamal encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ElGamalCiphertext implements Ciphertext {
	private GroupElement cipher1 = null;
	private GroupElement cipher2 = null;
	
	/**
	 * Create an instance of this container class 
	 * @param c1
	 * @param c2
	 */
	public ElGamalCiphertext(GroupElement c1, GroupElement c2){
		this.cipher1 = c1;
		this.cipher2 = c2;
	}
	
	public GroupElement getC1(){
		return cipher1;
	}
	
	public GroupElement getC2(){
		return cipher2;
	}
}
