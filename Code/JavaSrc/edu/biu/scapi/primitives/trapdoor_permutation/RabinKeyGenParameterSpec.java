package edu.biu.scapi.primitives.trapdoor_permutation;

import java.security.spec.AlgorithmParameterSpec;

/**
 * 
 * Interface for RabinParameterSpec
 *
 */
public class RabinKeyGenParameterSpec implements AlgorithmParameterSpec{
	int keySize = 65537;
	
	/**
	 * Constructor that set the keybits
	 * @param keySize
	 */
	public RabinKeyGenParameterSpec(int keySize) {
		this.keySize = keySize;
	}
	
	/**
	 * @return int - The key bits size
	 */
	public int getKeySize() {
		return keySize;
	}
}
