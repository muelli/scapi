/**
 * 
 */
package edu.biu.scapi.primitives.crypto.kdf.bc;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.generators.BaseKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;

import edu.biu.scapi.primitives.crypto.hash.TargetCollisionResistant;
import edu.biu.scapi.primitives.crypto.kdf.KeyDerivationFunction;
import edu.biu.scapi.tools.Translation.BCObjectCreator;

/** 
 * @author LabTest
*/
public class KdfISO18033 implements KeyDerivationFunction {

	BaseKDFBytesGenerator bcKdfGenerator;
	
	/**
	 * create the related bc kdf
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public KdfISO18033(TargetCollisionResistant hash) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		bcKdfGenerator = new KDF1BytesGenerator(BCObjectCreator.getInstance().getBCDigest(hash));
		
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
	 * generateParameters - generate the bc related parameters of type DerivationParameters
	 * @param shared - the input key 
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
}