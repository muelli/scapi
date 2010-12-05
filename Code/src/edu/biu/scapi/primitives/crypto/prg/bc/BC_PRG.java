/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prg.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.primitives.crypto.prg.PseudorandomGeneratorAbs;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/** 
 * @author LabTest
 */
public abstract class BC_PRG extends PseudorandomGeneratorAbs {
	
		private StreamCipher bcStreamCipher;//the underlying stream cipher of bc

	/** 
	 * Sets the StreamCipher of bc to adapt to.
	 * @param bcStreamCipher - the concrete StreamCipher of bc
	 */
	public BC_PRG(StreamCipher bcStreamCipher) {
		this.bcStreamCipher = bcStreamCipher;
	}
	
	public void init(KeySpec secretKey) {

		//set the parameters
		super.init(secretKey);
		
		//get the keyParameter relevant to the secretKey
		CipherParameters bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey);
		
		//init the underlying stream cipher. Note that the first argument is irrelevant and thus does not matter is true or false
		bcStreamCipher.init(false, bcParams);
	}

	/** 
	 * Initializes this prg with the secret key and the auxiliary parameters
	 * @param secretKey - the secret key
	 * @param params - the algorithm auxilary parameters
	 */
	public void init(KeySpec secretKey, AlgorithmParameterSpec params) {

		//set the parameters
		super.init(secretKey, params);
		
		//send the parameters converted to bc.
		CipherParameters bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey, params);
		
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
	 * @param in_bytes - the input bytes
	 * @param inOff - input offset
	 * @param len - length
	 * @param out_bytes - output bytes. The result of streaming the input bytes.
	 * @param outOff - output offset
	 */
	public void streamBytes(byte[] in_bytes, int inOff,
			int len, byte[] out_bytes, int outOff){

		bcStreamCipher.processBytes(in_bytes, inOff, len, out_bytes, outOff);
	}


}