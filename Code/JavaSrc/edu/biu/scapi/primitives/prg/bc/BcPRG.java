/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prg.bc;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.primitives.crypto.prg.PseudorandomGeneratorAbs;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/** 
 * @author LabTest
 */
public abstract class BcPRG extends PseudorandomGeneratorAbs {
	
		private StreamCipher bcStreamCipher;//the underlying stream cipher of bc
		private CipherParameters bcParams;
		

	/** 
	 * Sets the StreamCipher of bc to adapt to.
	 * @param bcStreamCipher - the concrete StreamCipher of bc
	 */
	public BcPRG(StreamCipher bcStreamCipher) {
		this.bcStreamCipher = bcStreamCipher;
	}
	
	public void init(SecretKey secretKey) {

		//set the parameters
		super.init(secretKey);
		
		//get the keyParameter relevant to the secretKey
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey);
		
		//init the underlying stream cipher. Note that the first argument is irrelevant and thus does not matter is true or false
		bcStreamCipher.init(false, bcParams);
	}

	/** 
	 * Initializes this prg with the secret key and the auxiliary parameters
	 * @param secretKey - the secret key
	 * @param params - the algorithm auxilary parameters
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		//set the parameters
		super.init(secretKey, params);
		
		//send the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey, params);
		
		//init the underlying stream cipher. Note that the first argument is irrelevant and thus does not matter is true or false
		bcStreamCipher.init(false, bcParams);
	}
	
	
	
	/** 
	 * Get the name of the algorithm through the underlying StreamCipher
	 * @return - the underlying algorithm name
	 */
	public String getAlgorithmName() {
		
		return bcStreamCipher.getAlgorithmName();
	}

	
	/** 
	 * Pass the byte to the underlying bc StreamCipher.
	 * @param bytein - the single byte to xor
	 */
	public void streamSingleByte(byte bytein) {
		
		bcStreamCipher.returnByte(bytein);
	}

	/** 
	 * Pass all the arguments to the underlying bc StreamCipher.
	 * @param inBytes - the input bytes
	 * @param inOff - input offset
	 * @param len - length
	 * @param outBytes - output bytes. The result of streaming the input bytes.
	 * @param outOff - output offset
	 */
	public void streamBytes(byte[] inBytes, int inOff,
			int len, byte[] outBytes, int outOff){

		bcStreamCipher.processBytes(inBytes, inOff, len, outBytes, outOff);
	}


}