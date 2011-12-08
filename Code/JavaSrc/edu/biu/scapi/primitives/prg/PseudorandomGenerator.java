package edu.biu.scapi.primitives.prg;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * General interface of pseudorandom generator. Every concrete class in this family should implement this interface. <p>
 * 
 * A pseudorandom generator (PRG) is a deterministic algorithm that takes a “short” uniformly distributed string, 
 * known as the seed, and outputs a longer string that cannot be efficiently distinguished from a uniformly 
 * distributed string of that length.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
  */
public interface PseudorandomGenerator {
	/** 
	 * Initializes this prg with the secret key
	 * @param secretKey - the secret key
	 */
	public void init(SecretKey secretKey);

	/** 
	 * Initializes this prg with the secret key and the auxiliary parameters
	 * @param secretKey secret key
	 * @param params the algorithm auxiliary parameters
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params);

	/**
	 * An object trying to use an instance of prg needs to check if it has already been initialized.
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized();
	
	/** 
	 * @return the parameter spec of this PRG
	 * @throws UnInitializedException if this object is not initialized
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException;

	/** 
	 * @return the secret key of this PRG
	 * @throws UnInitializedException if this object is not initialized
	 */
	public SecretKey getSecretKey() throws UnInitializedException;
	
	/** 
	 * @return the algorithm name. For example - RC4
	 */
	public String getAlgorithmName();

	/**
	 * Streams the prg bytes.
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outlen - the required output length
	 * @throws UnInitializedException if this object is not initialized
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset, int outlen) throws UnInitializedException;

	
}