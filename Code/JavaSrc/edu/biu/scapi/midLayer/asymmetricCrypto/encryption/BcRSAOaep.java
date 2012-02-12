package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.ciphertext.BasicAsymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/**
 * This class performs the RSA-OAEP encryption and decryption scheme.
 * By definition, this encryption scheme is CCA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcRSAOaep implements RSAOaep {
	
	private OAEPEncoding bcBlockCipher;				//the underling BC OAEP encoding
	private CipherParameters privateParameters;		//parameters contains the private key and the random
	private CipherParameters publicParameters;		//parameters contains the public key and the random
	private boolean forEncryption = true;
	private RSAPrivateKey privateKey;				
	private RSAPublicKey publicKey;		
	private AlgorithmParameterSpec params;			
	private SecureRandom random;					//source of randomness
	private boolean isInitialized = false;			//set to false until the init function is called
	
	/**
	 * Initialize this RSAOAEP encryption scheme with keys and AlgorithmParameterSpec.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param privateKey should be RSAPrivateKey
	 * @param params can be PAddingParameterSpec
	 */
	@Override
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws FactoriesException {
		//call the corresponding init function with default source of randomness
		init(publicKey, privateKey, params, new SecureRandom());
	}

	/**
	 * Initialize this RSAOAEP encryption scheme with keys, AlgorithmParameterSpec and source of randomness.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param privateKey should be RSAPrivateKey
	 * @param params can be PAddingParameterSpec
	 * @param random source of secure randomness
	 */
	@Override
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params, SecureRandom random) throws FactoriesException {
		//key should be RSA keys
		if(!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)){
			throw new IllegalArgumentException("keys should be instances of RSA keys");
		}
		//set the parameters
		this.publicKey = (RSAPublicKey) publicKey;
		this.privateKey = (RSAPrivateKey) privateKey;
		this.params = params;
		this.random = random;
		
		//create BC objects and initialize them
		initBCCipher();
		
		isInitialized = true; //mark this object as initialized
	}

	/**
	 * Initialize this RSAOAEP encryption scheme with keys.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param privateKey should be RSAPrivateKey
	 */
	@Override
	public void init(PublicKey publicKey, PrivateKey privateKey) {
		//call the corresponding init function with default source of randomness
		init(publicKey, privateKey, new SecureRandom());
	}

	/**
	 * Initialize this RSAOAEP encryption scheme with keys and source of randomness.
	 * After this initialization the user can encrypt and decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param privateKey should be RSAPrivateKey
	 * @param random source of secure randomness
	 */
	@Override
	public void init(PublicKey publicKey, PrivateKey privateKey,
			SecureRandom random) {
		//keys should be RSA keys
		if(!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)){
			throw new IllegalArgumentException("keys should be instances of RSA keys");
		}
		//set the parameters
		this.publicKey = (RSAPublicKey) publicKey;
		this.privateKey = (RSAPrivateKey) privateKey;
		this.random = random;
		
		//create BC objects and initialize them
		initBCCipher();
		
		isInitialized = true; //mark this object as initialized
	}

	/**
	 * Initialize this RSAOAEP encryption scheme with public key and AlgorithmParameterSpec.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param params can be PaddingParameterSpec
	 */
	@Override
	public void init(PublicKey publicKey, AlgorithmParameterSpec params) throws FactoriesException {
		//call the corresponding init function with default source of randomness
		init(publicKey, params, new SecureRandom());
	}

	/**
	 * Initialize this RSAOAEP encryption scheme with public key, AlgorithmParameterSpec and source of randomness.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param params can be PaddingParameterSpec
	 * @param random source of secure randomness
	 */
	@Override
	public void init(PublicKey publicKey, AlgorithmParameterSpec params,
			SecureRandom random) throws FactoriesException {
		//key should be RSA key
		if(!(publicKey instanceof RSAPublicKey)){
			throw new IllegalArgumentException("key should be instances of RSA key");
		}
		//set the parameters
		this.publicKey = (RSAPublicKey) publicKey;
		this.params = params;
		this.random = random;
		
		//create BC objects and initialize them
		initBCCipher();
		
		isInitialized = true; //mark this object as initialized
	}

	/**
	 * Initialize this RSAOAEP encryption scheme with public key.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 */
	@Override
	public void init(PublicKey publicKey) {
		//call the corresponding init function with default source of randomness
		init(publicKey, new SecureRandom());

	}

	/**
	 * Initialize this RSAOAEP encryption scheme with public key and source of randomness.
	 * After this initialization the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @param random source of secure randomness
	 */
	@Override
	public void init(PublicKey publicKey, SecureRandom random) {
		//key should be RSA key
		if(!(publicKey instanceof RSAPublicKey)){
			throw new IllegalArgumentException("key should be instances of RSA key");
		}
		//set the parameters
		this.publicKey = (RSAPublicKey) publicKey;
		this.random = random;
		
		//create BC objects and initialize them
		initBCCipher();
		
		isInitialized = true; //mark this object as initialized
	}

	/**
	 * Creates BC OAEPEncoding with BC RSABlindedEngine, translate the keys and random to BC CipherParameters
	 * and initialize BC object in encrypt mode.
	 * In order to decript, the decrypt function initialize them again to decrypt mode.
	 */
	private void initBCCipher(){
		
		//creates the OAEP encoding with RSABlindedEngine of BC
		bcBlockCipher = new OAEPEncoding(new RSABlindedEngine());
		//translate the keys and random to BC parameters
		privateParameters = BCParametersTranslator.getInstance().translateParameter(privateKey, random);
		publicParameters = BCParametersTranslator.getInstance().translateParameter(publicKey, random);
		//initialize the OAEP object with the cipherPerameters and for encryption
		bcBlockCipher.init(forEncryption, publicParameters);
	}
	
	@Override
	public boolean isInitialized() {
		return isInitialized;
	}

	@Override
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		//if this object is not initialized, throw exception
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//return the params
		return params;
	}

	/**
	 * @return the name of this Asymmetric encryption - "RSAOAEP"
	 */
	@Override
	public String getAlgorithmName() {
		return "RSAOAEP";
	}

	/**
	 * Encrypts the given plaintext according to the RSAOAEP algorithm using BC OAEPEncoding.
	 * @param plaintext the plaintext to encrypt
	 * @return Ciphertext contains the encrypted plaintext
	 */
	@Override
	public Ciphertext encrypt(Plaintext plaintext)
			throws UnInitializedException {
		//if the object is not initialized, throw UnInitialized exception
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//if the underlying BC object used to the encryption is in decrypt mode - change it
		if (!forEncryption){
			forEncryption = true;
			bcBlockCipher.init(forEncryption, publicParameters);
		}
		
		byte[] plaintextBytes = ((BasicPlaintext) plaintext).getText(); //get the plaintext bytes
		int inputBlockSize = bcBlockCipher.getInputBlockSize();
		
		//calculate the number of whole blocks
		int numberBlocksInCipher = plaintextBytes.length / inputBlockSize;
		int remainder = plaintextBytes.length % inputBlockSize;
		
		byte[] ciphertext = new byte[0]; //prepare the ciphertext array
		byte[] appendedCiphertext = new byte[0]; //in every round this array will hold the output of the previous rounds
		
		//encrypt every block in the plaintext and put the result in the ciphertext
		for (int i=0; i<numberBlocksInCipher; i++){
			try {
				//encrypt block using BC OAEP object
				byte[] outputBlock = bcBlockCipher.encodeBlock(plaintextBytes, i*inputBlockSize, inputBlockSize);
				//because there is no fixed output length for all the inputs, we can not allocate the space before we get the output.
				//therefore, in every loop we need to allocate a new space for this round output and the previous rounds output
				ciphertext = new byte[appendedCiphertext.length + outputBlock.length];
				
				//copy the previous rounds output to the ciphertext
				System.arraycopy(appendedCiphertext, 0, ciphertext, 0, appendedCiphertext.length);
				//copy the encrypted block of this round to the ciphertext
				System.arraycopy(outputBlock, 0, ciphertext, appendedCiphertext.length, outputBlock.length);
				
			} catch (InvalidCipherTextException e) {
				e.printStackTrace();
			}
		}
		//if the last block is not in block size, it needs a special treatment
		if (remainder != 0){
			try {
				byte[] outputBlock = bcBlockCipher.encodeBlock(plaintextBytes, numberBlocksInCipher*inputBlockSize, remainder);
				//because there is no fixed output length for all the inputs, we can not allocate the space before we get the output.
				//therefore, in every loop we need to allocate a new space for this round output and the previous rounds output
				ciphertext = new byte[appendedCiphertext.length + outputBlock.length];
				//copy the previous rounds output to the ciphertext
				System.arraycopy(appendedCiphertext, 0, ciphertext, 0, appendedCiphertext.length);
				//copy the encrypted block of this round to the ciphertext
				System.arraycopy(outputBlock, 0, ciphertext, appendedCiphertext.length, outputBlock.length);
			} catch (InvalidCipherTextException e) {
				e.printStackTrace();
			}
		}
		
		//return a ciphertext with the encrypted plaintext
		return new BasicAsymCiphertext(ciphertext);
	}

	/**
	 * Decrypts the given ciphertext according to the RSAOAEP algorithm using BC OAEPEncoding.
	 * @param cipher the ciphertext to decrypt
	 * @return Plaintext contains the decrypted ciphertext
	 */
	@Override
	public Plaintext decrypt(Ciphertext cipher) {
		//if there is no private key can not decrypt, throw exception
		if (privateKey == null){
			throw new IllegalStateException("in order to decrypt a message, this object must be initialized with private key");
		}
		//cipher must be of type BasicAsymCiphertext
		if (!(cipher instanceof BasicAsymCiphertext)){
			throw new IllegalArgumentException("The ciphertext has to be of type BasicAsymCiphertext");
		}
		//if the underlying BC object used to the decryption is in encrypt mode - change it
		if (forEncryption){
			forEncryption = false;
			bcBlockCipher.init(forEncryption, privateParameters);
		}
		
		byte[] ciphertext = ((BasicAsymCiphertext) cipher).getBytes();
		int outputBlockSize = bcBlockCipher.getInputBlockSize();
		
		//calculate the number of whole blocks
		int numberBlocksInCipher = ciphertext.length / outputBlockSize;
		int remainder = ciphertext.length % outputBlockSize;
		
		byte[] plaintext = new byte[0]; //prepare the plaintext array
		byte[] appendedPlaintext = new byte[0]; //in every round this array will hold the output of the previous rounds
		
		//decrypt every block in the ciphertext and put the result in the paddedPlaintext
		for (int i=0; i<numberBlocksInCipher; i++){
			try {
				//decrypt block using BC OAEP object
				byte[] plaintextBlock = bcBlockCipher.decodeBlock(ciphertext, i*outputBlockSize, outputBlockSize);
				//because there is no fixed output length for all the inputs, we can not allocate the space before we get the output.
				//therefore, in every loop we need to allocate a new space for this round output and the previous rounds output
				plaintext = new byte[appendedPlaintext.length + plaintextBlock.length];
				//copy the previous rounds output to the ciphertext
				System.arraycopy(appendedPlaintext, 0, plaintext, 0, appendedPlaintext.length);
				//copy the encrypted block of this round to the ciphertext
				System.arraycopy(plaintextBlock, 0, plaintext, appendedPlaintext.length, plaintextBlock.length);
			} catch (InvalidCipherTextException e) {
				e.printStackTrace();
			}
		}
		
		//if the last block is not in block size, it needs a special treatment
		if (remainder != 0){
			try {
				//decrypt block using BC OAEP object
				byte[] plaintextBlock = bcBlockCipher.decodeBlock(ciphertext, numberBlocksInCipher*outputBlockSize, outputBlockSize);
				//because there is no fixed output length for all the inputs, we can not allocate the space before we get the output.
				//therefore, in every loop we need to allocate a new space for this round output and the previous rounds output
				plaintext = new byte[appendedPlaintext.length + plaintextBlock.length];
				
				//copy the previous rounds output to the ciphertext
				System.arraycopy(appendedPlaintext, 0, plaintext, 0, appendedPlaintext.length);
				//copy the encrypted block of this round to the ciphertext
				System.arraycopy(plaintextBlock, 0, plaintext, appendedPlaintext.length, plaintextBlock.length);
			} catch (InvalidCipherTextException e) {
				e.printStackTrace();
			}
		}
		//return a plaintext with the decrypted ciphertext
		return new BasicPlaintext(plaintext);
	}
	
	/**
	 * Generates a KeyPair contains set of RSAPublicKEy and RSAPrivateKey using default source of randomness.
	 * @param keyParams RSAPssParameterSpec
	 * @return KeyPair contains keys for this RSAPss object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAPssParameterSpec
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//call the static function that generates RSA key pair
		return keyGen(keyParams);
		
	}

	/**
	 * Generates a KeyPair contains set of RSAPublicKEy and RSAPrivateKey using the given source of randomness.
	 * @param keyParams RSAPssParameterSpec
	 * @return KeyPair contains keys for this RSAPss object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAPssParameterSpec
	 */
	@Override
	public KeyPair generateKey(AlgorithmParameterSpec keyParams,
			SecureRandom random) throws InvalidParameterSpecException  {
		//call the static function that generates RSA key pair
		return keyGen(keyParams, random);
	}
	
	/**
	 * Static function that generates RSA key pair using default source of randomness.
	 * @param keyParams RSAPssParameterSpec
	 * @return KeyPair contains keys for this RSAPss object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAPssParameterSpec
	 */
	public static KeyPair keyGen(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//call the static keyGen function with default source of randomness
		return keyGen(keyParams, new SecureRandom());
	}
	
	/**
	 * Static function that generates RSA key pair using the given source of randomness.
	 * @param keyParams RSAPssParameterSpec
	 * @return KeyPair contains keys for this RSAPss object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAPssParameterSpec
	 */
	public static KeyPair keyGen(AlgorithmParameterSpec keyParams, SecureRandom random) throws InvalidParameterSpecException {
		//if keyParams is not the expected, throw exception
		if (!(keyParams instanceof RSAKeyGenParameterSpec)){
			throw new InvalidParameterSpecException("keyParams should be instance of RSAKeyGenParameterSpec");
		}
		
		try {
			//generates keys using the KeyPairGenerator
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keyParams, random);
			return generator.generateKeyPair(); 
		} catch(InvalidAlgorithmParameterException e){
			//shouldn't occur since the parameterSpec is valid for RSA
		} catch (NoSuchAlgorithmException e) {
			//shouldn't occur since RSA is a valid algorithm
			e.printStackTrace();
		}
		return null;
	}
}
