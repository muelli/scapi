package edu.biu.scapi.midLayer.symmetricCrypto.encryption;
/**
 * This class implements common functionality of Symmetric Encryption Schemes that must use a random IV
 */
import java.security.InvalidKeyException;
import java.security.SecureRandom; //TODO decide if we import from here or sun.security.provider.
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.SecretKeyGeneratorUtil;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.SymKeyGenParameterSpec;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;

abstract class EncWithIVAbs implements SymmetricEnc {
	protected PseudorandomPermutation prp;
	//private SecretKey secretKey;
	//private byte[] iv;
	protected SecureRandom random;
	
	//By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.
	public EncWithIVAbs(PseudorandomPermutation prp) {
		this.prp = prp;
	}

	//This protected function must be implemented in each concrete class.
	//In CTREnc this function performs the CTR mode of operation.
	//In CBCEnc this function performs the CBC mode of operation.
	protected abstract IVCiphertext encAlg(byte[] plaintext, byte[] iv) throws UnInitializedException;
	
	public void init(SecretKey secretKey) throws InvalidKeyException{
		prp.init(secretKey); //Do we need to check that prp is not null? What if it is? What if the concrete implementation doesn't instantiate the prp?
		random = new SecureRandom();
	}
	public void init(SecretKey secretKey, SecureRandom random) throws InvalidKeyException{
		prp.init(secretKey);
		this.random = random; 
	}
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidParameterSpecException{
		prp.init(secretKey, params); //Do we need to check that prp is not null? What if it is? What if the concrete implementation doesn't instantiate the prp?
		random = new SecureRandom();
	}
	public void init(SecretKey secretKey, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidParameterSpecException{
		prp.init(secretKey, params); //Do we need to check that prp is not null? What if it is? What if the concrete implementation doesn't instantiate the prp?
		this.random = random;
	}
	
	public boolean isInitialized(){
		return prp.isInitialized();
	}
	
	public AlgorithmParameterSpec getParams() throws UnInitializedException{
		return prp.getParams();
	}
	
	//This function generates an authenticated key and uses SCAPI’s default source of randomness. 
	//The given keySize is in bits.
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
	
	//Generate a secret key for a certain key size and and a source of randomness.
	public SecretKey generateKey(AlgorithmParameterSpec keySize, SecureRandom random ) throws InvalidParameterSpecException{
		if(! (keySize instanceof SymKeyGenParameterSpec) ){
			throw new InvalidParameterSpecException("keySize has to be of type SymKeyGenParameterSpec");
		}
		SymKeyGenParameterSpec params = (SymKeyGenParameterSpec)keySize;
		
		return SecretKeyGeneratorUtil.generateKey(params.getEncKeySize(), prp.getAlgorithmName(), random);
		
	}
	
	
	//This function encrypts a plaintext. It lets the system choose the random IV. 
	//It returns an IVCiphertext, which contains the IV used and the encrypted data.
	public SymmetricCiphertext encrypt(Plaintext plaintext) throws UnInitializedException{
		if (!isInitialized())
			throw new UnInitializedException();
		byte[] iv = new byte[prp.getBlockSize()]; 
		this.random.nextBytes(iv);
		IVCiphertext cipher = null;
		try {
			cipher =  (IVCiphertext) encrypt(plaintext, iv);
		} catch (IllegalBlockSizeException e) {
			
			e.printStackTrace();
		}
		return cipher;
	}
	
	//This function encrypts a plaintext. It lets the system choose the random IV. 
	//It returns an IVCiphertext, which contains the IV used and the encrypted data.
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv) throws UnInitializedException, IllegalBlockSizeException{
		//this.iv = iv;
		if(iv.length != prp.getBlockSize()){
			throw new IllegalBlockSizeException("The length of the IV passed is not equal to the block size of current PRP");
		}
		BasicPlaintext text = (BasicPlaintext)plaintext;
		IVCiphertext cipher =  encAlg(text.getText(),iv);
		return cipher;
	}
	
}
