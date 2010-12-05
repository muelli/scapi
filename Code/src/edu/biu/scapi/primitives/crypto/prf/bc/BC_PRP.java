/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import edu.biu.scapi.primitives.crypto.prf.PseudorandomPermutationAbs;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/** 
* @author LabTest
 */
public abstract class BC_PRP extends PseudorandomPermutationAbs {
	
	private BlockCipher bcBlockCipher = null;//bc block cipher
	private CipherParameters bcParams = null;//bc paramters
	private boolean forEncryption = true;//set for true. If decryption is needed the flag will be set to false. DO NOT CHANGE SINCE THE INIT IS FOR TRUE

	/** 
	 * @param bcBlockCipher - the underlying bc block cipher
	 */
	public BC_PRP(BlockCipher bcBlockCipher) {
		
		this.bcBlockCipher = bcBlockCipher;
	}

	
	/** 
	 */
	public String getAlgorithmName() {
		
		return bcBlockCipher.getAlgorithmName();
	}

	/** 
	 */
	public int getBlockSize() {
		return bcBlockCipher.getBlockSize();
	}

	/** 
	 * @param inBytes		 
	 * @param inOff
	 * @param outBytes
	 * @param outOff
	 */
	public void computetBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) {
		
		//if the bc block cipher is not already in encryption mode init the block cipher with forEncryption=true
		if(forEncryption==false){
			forEncryption = true;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//do the computeBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}

	/** 
	 * @param inOff
	 * @param inBytes
	 * @param outBytes
	 * @param outOff
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff) {
		
		//if the bc block cipher is not already in decryption mode init the block cipher with forEncryption=false
		if(forEncryption==true){
			forEncryption = false;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//do the invertBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}

	
	/** 
	 * Creates the relevant bc parameters to pass when inverting or computing.
	 * @param secretKey - secret key
	 */
	public void init(KeySpec secretKey) {
		
		//init parameters
		super.init(secretKey);
		
		//get the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey);
		
		bcBlockCipher.init(true, bcParams);
			
	}

	/** 
	 * Creates the relevant bc parameters to pass when inverting or computing.
	 * @param secretKey - secret key
	 * @param params - algorithm parameters
	 */
	public void init(KeySpec secretKey, AlgorithmParameterSpec params) {

		//init parameters
		super.init(secretKey,params);
		
		//send the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey, params);
		
		bcBlockCipher.init(true, bcParams);
		
	}
}