package edu.biu.scapi.midLayer.symmetricCrypto.encryption;
/**
 * This class implements common functionality of Symmetric Encryption Schemes that must use a random IV
 */
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.SecretKeyGeneratorUtil;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.SymKeyGenParameterSpec;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;
import edu.biu.scapi.tools.Factories.PrfFactory;

abstract class EncWithIVAbs implements SymmetricEnc {
	protected PseudorandomPermutation prp;
	protected SecureRandom random;
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets and initialized Pseudorandom permutation. This implies that there is
	 * no need to call init afterwards.
	 * @param prp specific Pseudorandom permutation, for example AES.
	 * @throws UnInitializedException
	 */
	public EncWithIVAbs(PseudorandomPermutation prp) throws UnInitializedException {
		if(!(prp.isInitialized())) {
			throw new UnInitializedException("The PRP object must be initilized");
		}	
		this.prp = prp;
	}

	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * The init function must be called subsequently in order to work properly with this encryption object.
	 * @param prp the name of a specific Pseudorandom permutation, for example "AES".
	 */
	public EncWithIVAbs(String prpName) throws FactoriesException {
		// Creates a prp object and set this.prp to it
		prp = (PseudorandomPermutation) PrfFactory.getInstance().getObject(prpName);
	}
	
	//This protected function must be implemented in each concrete class.
	//In CTREnc this function performs the CTR mode of operation.
	//In CBCEnc this function performs the CBC mode of operation.
	protected abstract IVCiphertext encAlg(byte[] plaintext, byte[] iv) throws UnInitializedException;
	
	/**
	 * Initialize the encryption scheme with a Secret Key.
	 */
	public void init(SecretKey secretKey) throws InvalidKeyException{
		prp.init(secretKey); //Do we need to check that prp is not null? What if it is? What if the concrete implementation doesn't instantiate the prp?
		random = new SecureRandom();
	}

	/**
	 * Initialize the encryption scheme with a Secret Key and a user provided source of randomness.
	 */
	public void init(SecretKey secretKey, SecureRandom random) throws InvalidKeyException{
		prp.init(secretKey);
		this.random = random; 
	}

	/**
	 * Initialize the encryption scheme with a Secret Key and relevant parameters.
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidParameterSpecException{
		prp.init(secretKey, params); //Do we need to check that prp is not null? What if it is? What if the concrete implementation doesn't instantiate the prp?
		random = new SecureRandom();
	}
	/**
	 * Initialize the encryption scheme with a Secret Key, other relevant parameters and a user provided source of randomness.
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidParameterSpecException{
		prp.init(secretKey, params); //Do we need to check that prp is not null? What if it is? What if the concrete implementation doesn't instantiate the prp?
		this.random = random;
	}
	
	/**
	 * Checks if this object has been initialized
	 * @return true, if already initialized <p> false, otherwise.
	 * 
	 */
	public boolean isInitialized(){
		return prp.isInitialized();
	}
	
	
	/**
	 * @return the parameters set upon initialization.
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException{
		return prp.getParams();
	}
	
	/**
	 * This function generates a secret key and uses SCAPI’s default source of randomness.<p>
	 * The given keySize is in bits.
	 * @return the Secret Key generated for this specific encrytpion algorithm. 
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keySize ) throws InvalidParameterSpecException{
		//If the source of randomness has been previously set, then use it.
		//If not, then we do not need to set it at this stage. It will be set with one of the init functions. However, 
		//if we call "generateKey(keySize, this.random)" where the SecureRandom argument is null, then for some provider implementations, 
		//like SunJCE, it may work (if no source of randomness is provided, it uses SunJCE.RANDOM), but for others it may not.
		//Therefore, we should not leave this to good or bad luck!!
		SecretKey key; 
		if(this.random != null){
			key = generateKey(keySize, this.random);
		}else{
			key = generateKey(keySize, new SecureRandom());
		}
		return key;
	}
	
	/**
	 * Generate a secret key for a certain key size and and a source of randomness.
	 * @return the Secret Key generated for this specific encrytpion algorithm.
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keySize, SecureRandom random ) throws InvalidParameterSpecException{
		if(! (keySize instanceof SymKeyGenParameterSpec) ){
			throw new InvalidParameterSpecException("keySize has to be of type SymKeyGenParameterSpec");
		}
		SymKeyGenParameterSpec params = (SymKeyGenParameterSpec)keySize;
		
		return SecretKeyGeneratorUtil.generateKey(params.getEncKeySize(), prp.getAlgorithmName(), random);
		
	}
	
	
	/**
	 * This function encrypts a plaintext. It lets the system choose the random IV.
	 * @return  an IVCiphertext, which contains the IV used and the encrypted data.
	 */
	public SymmetricCiphertext encrypt(Plaintext plaintext) throws UnInitializedException{
		if (!isInitialized())
			throw new UnInitializedException();
		
		//Allocate space for the IV.
		byte[] iv = new byte[prp.getBlockSize()];
		//Generate a random IV
		this.random.nextBytes(iv);
		
		//Encrypt the plaintext with the just chosen random IV.
		IVCiphertext cipher = null;
		try {
			cipher =  (IVCiphertext) encrypt(plaintext, iv);
		} catch (IllegalBlockSizeException e) {
			
			e.printStackTrace();
		}
		return cipher;
	}
	
	/**
	 * This function encrypts a plaintext. It lets the system choose the random IV.
	 * @return an IVCiphertext, which contains the IV used and the encrypted data. 
	 */
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv) throws UnInitializedException, IllegalBlockSizeException{
		//Check validity of IV's length:
		if(iv.length != prp.getBlockSize()){
			throw new IllegalBlockSizeException("The length of the IV passed is not equal to the block size of current PRP");
		}
		//Each implementing class must write the actual encryption algorithm in "encAlg" function. 
		BasicPlaintext text = (BasicPlaintext)plaintext;
		IVCiphertext cipher =  encAlg(text.getText(),iv);
		return cipher;
	}
	
}
