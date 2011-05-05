/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prg;

import java.security.spec.AlgorithmParameterSpec;


import javax.crypto.SecretKey;

/** 
 * @author LabTest
 */
public abstract class PseudorandomGeneratorAbs implements PseudorandomGenerator {
	
	protected SecretKey secretKey = null;//secrete key
	protected AlgorithmParameterSpec params = null;//algorithm parameters

	/** 
	 * Initializes this prg with the secret key
	 * @param secretKey - the secrete key
	 */
	public void init(SecretKey secretKey) {

		//init the key. Further initialization should be implemented in the derived concrete class.
		this.secretKey = secretKey;
	}

	/** 
	 * Initializes this prg with the secret key and the auxiliary parameters
	 * @param secretKey
	 * @param params
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		//init the parameters. Further initialization should be implemented in the derived concrete class.
		this.secretKey = secretKey;
		this.params = params;
	}

	/** 
	 * @return The algorithm name
	 */
	public abstract String getAlgorithmName();

	/** 
	 * @param bytein - the single byte to xor
	 */
	public abstract void streamSingleByte(byte bytein);

	/** 
	 * @param inBytes - the input bytes
	 * @param inOff - input offset
	 * @param len - length
	 * @param outBytes - output bytes. The result of streaming the input bytes.
	 * @param outOff - output offset
	 */
	public abstract void streamBytes(byte[] inBytes, int inOff,	int len, byte[] outBytes, int outOff);
	/** 
	 * @return the parameters of this prp
	 */
	public AlgorithmParameterSpec getParams() {
		
		return params;
	}

	/** 
	 * @return
	 */
	public SecretKey getSecretKey() {

		return secretKey;
	}
}