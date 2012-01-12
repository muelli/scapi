package edu.biu.scapi.midLayer.symmetricCrypto.keys;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is a container for the data needed to generate a key for Symmetric Encryption.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class SymKeyGenParameterSpec implements AlgorithmParameterSpec {

		private int encKeySize;
		
		public SymKeyGenParameterSpec(int encKeySize){
			this.encKeySize = encKeySize;
		}
		
		public int getEncKeySize() {
			return encKeySize;
		}
}
