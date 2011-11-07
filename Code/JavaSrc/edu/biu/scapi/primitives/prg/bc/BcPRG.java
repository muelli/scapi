/**
 * 
 */
package edu.biu.scapi.primitives.prg.bc;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.prg.PseudorandomGeneratorAbs;
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
	 * Pass all the arguments to the underlying bc StreamCipher, which stream the bytes.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outlen - length
	 * @throws UnInitializedException 
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset,	int outLen) throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//check that the offset and the length are correct
		if ((outOffset > outBytes.length) || ((outOffset + outLen) > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//in array filled with zeroes
		byte[] inBytes = new byte[outLen];
		
		//out array filled with pseudorandom bytes (that were xored with zeroes in the in array)
		bcStreamCipher.processBytes(inBytes, 0, outLen, outBytes, outOffset);
	}


}