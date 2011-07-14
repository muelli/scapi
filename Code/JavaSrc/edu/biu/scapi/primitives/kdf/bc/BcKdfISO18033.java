/**
 * 
 */
package edu.biu.scapi.primitives.kdf.bc;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.generators.BaseKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;

import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.tools.Factories.BCFactory;

/** 
 * @author LabTest
*/
public class BcKdfISO18033 implements KeyDerivationFunction {

	BaseKDFBytesGenerator bcKdfGenerator;
	
	/**
	 * create the related bc kdf
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public BcKdfISO18033(String hash) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		
		//pass a digest to the KDF.
		bcKdfGenerator = new KDF1BytesGenerator(BCFactory.getInstance().getDigest(hash));
		
	}
	
	
	public SecretKey generateKey(SecretKey key, int len) {
		
		return generateKey(key, len, null);
	}

	/**
	 * 
	 */
	public SecretKey generateKey(SecretKey key, int outLen, byte[] iv) {
		
		byte[] generatedKey = new byte[outLen];//generated key bytes
		
		//generate the related derivation parameter for bc
		bcKdfGenerator.init(generateParameters(key.getEncoded(), iv));
		
		//generate the actual key bytes
		bcKdfGenerator.generateBytes(generatedKey, 0, outLen);
		
		//convert to key
		return new SecretKeySpec(generatedKey, "KDF");
	}


	/**
	 * 
	 */
	public void generateKey(byte[] inKey, int inOff, int inLen, byte[] outKey,
			 int outOff,int outLen) {
		
		bcKdfGenerator.init(generateParameters(inKey,null));
		
		bcKdfGenerator.generateBytes(outKey, 0, outLen);
		
	}
	
	/**
	 * 
	 * Generate the bc related parameters of type DerivationParameters
	 * @param shared the input key 
	 * @param iv
	 */
	private DerivationParameters generateParameters(byte[] shared, byte[] iv){
		
		if(iv==null){//iv is not provided
			
			return new ISO18033KDFParameters(shared);
		}
		else{ //iv is provided. Pass to the KDFParameters
			return new KDFParameters(shared, iv);
		}
		
	}


	/**
	 * 
	 */
	public void init(SecretKey secretKey) {
		// TODO Auto-generated method stub
		
	}


	/**
	 * 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {
		// TODO Auto-generated method stub
		
	}


	/**
	 * 
	 */
	public boolean isInitialized() {
		// initialization is not needed
		return true;
	}
}