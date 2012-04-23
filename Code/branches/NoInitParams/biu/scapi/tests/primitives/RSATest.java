package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.trapdoorPermutation.RabinKeyGenParameterSpec;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutation;
import edu.biu.scapi.primitives.trapdoorPermutation.cryptopp.CryptoPpRabinElement;

/**
 *
 * This class tests the performance and correctness of RSA algorithm.
 * The test vectors are taken from ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip.
 * 
 * Unlike other algorithm classes this class is abstract. 
 * Most algorithms have a general class not depending on the wrapped library, however the similar vector test is not
 * sufficient in this case since the creation of a TPElment differs for each library implementation. Thus there is 
 * a special function <code> createElement <code> that calls the concrete derived class to create the relevent library element.  
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public abstract class RSATest extends TrapdoorPermutationTest {

	/**
	 * Sets the given TrapdoorPermutation object, adds data for the test vectors.
	 */
	public RSATest(TrapdoorPermutation tp) {
		super(tp);
		
		//creates an 1024 RSA with random variables to test
		RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(65537));
		
		
		//creates an 2048 RSA with random variables to test 
		RSAKeyGenParameterSpec spec1 = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65537));
		
		//creates an 4096 RSA with random variables to test 
		RSAKeyGenParameterSpec spec2 = new RSAKeyGenParameterSpec(4096, BigInteger.valueOf(65537));
		
		//adds the algorithmParameterSpec to the compute-invert test vector. A random element and keys will be chosen and tested.
		addDataInvertCompute(null, spec);
		addDataInvertCompute(null, spec1);
		addDataInvertCompute(null, spec2);
		
		//fills the compute and compare test vectors of rsa
		rsaTestVector();
	}
	
	
	/**
	 * Adds tests to the RSA test vectors.
	 * Each test contains specific input, specific keys and expected output
	 */
	private void rsaTestVector() throws IllegalArgumentException {
		try {
			//declares all the arguments of the keys
			BigInteger modulus = new BigInteger("bbf82f090682ce9c2338ac2b9da871f7368d07eed41043a440d6b6f07454f51f" + 
												"b8dfbaaf035c02ab61ea48ceeb6fcd4876ed520d60e1ec4619719d8a5b8b807f" +  
												"afb8e0a3dfc737723ee6b4b7d93a2584ee6a649d060953748834b2454598394e" +
												"e0aab12d7b61a51f527a9a41f6c1687fe2537298ca2a8f5946f8e5fd091dbdcb"
												, 16);
			BigInteger e = new BigInteger("11", 16);
			
			BigInteger p = new BigInteger("eecfae81b1b9b3c908810b10a1b5600199eb9f44aef4fda493b81a9e3d84f632" + 
										  "124ef0236e5d1e3b7e28fae7aa040a2d5b252176459d1f397541ba2a58fb6599", 16);
			
			BigInteger q = new BigInteger("c97fb1f027f453f6341233eaaad1d9353f6c42d08866b1d05a0f2035028b9d86" + 
										  "9840b41666b42e92ea0da3b43204b5cfce3352524d0416a5a441e700af461503", 16);
			
			BigInteger phi = (p.add(new BigInteger("-1"))).multiply(q.add(new BigInteger("-1")));
			BigInteger d = e.modInverse(phi);
			
			BigInteger dp = new BigInteger("54494ca63eba0337e4e24023fcd69a5aeb07dddc0183a4d0ac9b54b051f2b13e" + 
										   "d9490975eab77414ff59c1f7692e9a2e202b38fc910a474174adc93c1f67c981", 16);
			
			BigInteger dq = new BigInteger("471e0290ff0af0750351b7f878864ca961adbd3a8a7e991c5c0556a94c3146a7" +
										   "f9803f8f6f8ae342e931fd8ae47a220d1b99a495849807fe39f9245a9836da3d", 16);
			
			BigInteger qInv = new BigInteger("b06c4fdabb6301198d265bdbae9423b380f271f73453885093077fcd39e2119f" +
											 "c98632154f5883b167a967bf402b4e9e2e0f9656e698ea3666edfb25798039f7", 16);
			
			//creates public and private RSAkeySpec  
			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, e);
			RSAPrivateKeySpec privKeySpec = new RSAPrivateCrtKeySpec(modulus, e, d, p, q, dp, dq, qInv);
			
			//generates PublicKey and PrivateKey from the KeySpec
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = factory.generatePublic(pubKeySpec);
			PrivateKey privKey = factory.generatePrivate(privKeySpec);
			
			//builds a RSA element with the input value
			BigInteger value = new BigInteger(
								"00eb7a19ace9e3006350e329504b45e2ca82310b26dcd87d5c68f1eea8f55267" + 
								"c31b2e8bb4251f84d7e0b2c04626f5aff93edcfb25c9c2b3ff8ae10e839a2ddb" + 
								"4cdcfe4ff47728b4a1b7c1362baad29ab48d2869d5024121435811591be392f9" + 
								"82fb3e87d095aeb40448db972f3ac14f7bc275195281ce32d2f1b76d4d353e2d", 16);
			
			TPElement element = createElement(modulus, value);
			
			//build RSA element with the computation result value
			BigInteger computeResultValue = new BigInteger(
										"1253e04dc0a5397bb44a7ab87e9bf2a039a33d1e996fc82a94ccd30074c95df7" +
										"63722017069e5268da5d1c0b4f872cf653c11df82314a67968dfeae28def04bb" +	
										"6d84b1c31d654a1970e5783bd6eb96a024c2ca2f4a90fe9f2ef5c9c140e5bb48" + 
										"da9536ad8700c84fc9130adea74e558d51a74ddf85d8b50de96838d6063e0955", 16);
			
			TPElement computeResult = createElement(modulus, computeResultValue);
			
			//adds to the test vector the elements and the keys
			addData(element, computeResult, pubKey, privKey);

		} catch (InvalidKeySpecException e1) {
			//shouldn't occur since RSA is a valid KeySpec
			Logging.getLogger().log(Level.WARNING, e1.toString());
		} catch (NoSuchAlgorithmException e1) {
			//shouldn't occur since RSA is a valid algorithm
			Logging.getLogger().log(Level.WARNING, e1.toString());
		}
	}


	/**
	 * Creates a RSA element through a call to the derived class.
	 * @param modulus RSA modulus
	 * @param value the required element value
	 * @return TPElement the created element
	 */
	protected abstract TPElement createElement(BigInteger modulus, BigInteger value);

	/**
	 * Test the case that the given argument is not a RSA element. 
	 * @param file the output file
	 */
	protected void wrongArgumentType(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//init the tp
			tp.setKey(testDataVector.get(0).publicKey, testDataVector.get(0).privateKey);
			//creates a rabin element
			CryptoPpRabinElement element = new CryptoPpRabinElement(tp.getModulus());
			
			//calls the compute function and send the rabin object
			tp.compute(element);
		//the expected result of this test is IllegalArgumentException
		} catch(IllegalArgumentException e){
			testResult = "Success: The expected exception \"IllegalArgumentException\" was thrown";
		//any other exception is a failure
		} catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalArgumentException\" was thrown";
		}
		
		//prints the result to the output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Wrong argument type,Wrong behavior,,," + testResult);
	}
	
	/**
	 * Test the case that the given key is not a RSA key. 
	 * @param file the output file
	 */
	protected void wrongKeyType(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//create a RabinKeyGenParameterSpec to init the tp 
			RabinKeyGenParameterSpec spec = new RabinKeyGenParameterSpec(1024);
			
			//init the RSA permutation with Rabin spec
			tp.generateKey(spec);
			
			//the expected result of this test is InvalidParameterSpecException
		} catch(InvalidParameterSpecException e){
			testResult = "Success: The expected exception \"InvalidParameterSpecException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"InvalidParameterSpecException\" was thrown";
		}
		
		//prints the result to the output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Wrong key type,Wrong behavior,,," + testResult);	
	}
	
}
