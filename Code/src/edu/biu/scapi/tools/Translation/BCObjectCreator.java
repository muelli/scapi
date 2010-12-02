/**
 * 
 */
package edu.biu.scapi.tools.Translation;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;

import edu.biu.scapi.primitives.crypto.trapdoor_permutation.TrapdoorPermutation;
import edu.biu.scapi.primitives.crypto.prf.PseudorandomPermutation;
import edu.biu.scapi.primitives.crypto.hash.Hash;
import edu.biu.scapi.primitives.crypto.prg.PseudorandomGenerator;

/** 
  * @author LabTest
  */
public class BCObjectCreator {
	private BCClassTranslator bCClassTranslator;
	private BCParametersTranslator bCParametersTranslator;
	private static final BCObjectCreator objectCreator = new BCObjectCreator();//singleton

	/**
	 * Empty constructor should be private since this class is singleton and we want to prevent user creation
	 * of this class
	 */
	private BCObjectCreator(){
		bCClassTranslator = BCClassTranslator.getInstance();
		bCParametersTranslator = BCParametersTranslator.getInstance();
		
	};
	
	/** 
	 * @return the singleton object
	 */
	public static BCObjectCreator getInstance() {
		return objectCreator;
		
	}
	
	/** 
	 * @param trapdoorPermutation
	 * @return
	 */
	public AsymmetricBlockCipher getBCAsymmetricBlockCipher(
			TrapdoorPermutation trapdoorPermutation) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param name
	 * @param params
	 * @return
	 */
	public AsymmetricBlockCipher getBCAsymmetricBlockCipher(String name,
			AlgorithmParameterSpec params) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param prp
	 * @return
	 */
	public BlockCipher getBCBlockCipher(PseudorandomPermutation prp) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param params
	 * @param name
	 * @return
	 */
	public BlockCipher getBCBlockCipher(AlgorithmParameterSpec params,
			String name) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param hash - a hash object from which we can take attributes to pass to the classTranslator
	 * @return
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public Digest getBCDigest(Hash hash) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		
		//pass the name of the digest through the name of the hash
		return bCClassTranslator.loadBCDigest(hash.getAlgorithmName());
		
	}

	/** 
	 * @param name - the name of the digest to load
	 * @param params - auxilary parameters to pass
	 * @return
	 * @throws ClassNotFoundException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public Digest getBCDigest(String name, AlgorithmParameterSpec params) throws InstantiationException, IllegalAccessException, ClassNotFoundException {

		//pass the name of the digest 
		return bCClassTranslator.loadBCDigest(name);
	}

	/** 
	 * @param name
	 * @param params
	 * @return
	 */
	public StreamCipher getBCStreamCipher(String name,
			AlgorithmParameterSpec params) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @param prg
	 * @return
	 */
	public StreamCipher getBCStreamCipher(PseudorandomGenerator prg) {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	
}