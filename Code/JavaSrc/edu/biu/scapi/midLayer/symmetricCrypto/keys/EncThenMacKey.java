/**
 * 
 */
package edu.biu.scapi.midLayer.symmetricCrypto.keys;

import javax.crypto.SecretKey;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class EncThenMacKey implements AuthEncKey {
	
	private static final long serialVersionUID = -5448970400092157445L;

	private SecretKey encKey= null;
	
	private SecretKey macKey = null;
	
	public EncThenMacKey(SecretKey encKey, SecretKey macKey){
		this.encKey = encKey;
		this.macKey = macKey;
	}
	
	public SecretKey getEncryptionKey(){
		return encKey;
	}
	
	public SecretKey getMacKey() {
		return macKey;
	}
	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		
		return "EncThenMac";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		throw new UnsupportedOperationException("Get the encoded MAC key, or the encoded encryption key separately");
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		throw new UnsupportedOperationException("No format defined for algorithm Encrypt-Then-MAC");
	}

}
