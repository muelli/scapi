package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.logging.Level;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.bc.BcDlogECFp;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;

/**
 * This class tests the performance and correctness of any implemented Dlog group over Zp*.
 * There is no known test vectors.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class DlogZpTest extends DlogGroupTest{

	/**
	 * Sets the given DlogZp object.
	 */
	public DlogZpTest(DlogGroup dlog) {
		super(dlog);
		
	}
	
	
	/**
	 * Runs all the required wrong behavior tests for Dlog Zp.
	 * @param file the output file
	 */
	public void wrongBehavior(PrintWriter file) {
		//calls the wrong behavior functions of DlogGroup and adds the wrong behavior of Dlog over Zp
		super.wrongBehavior(file);
		wrongInitialization(file); //case that the init parameters are not legal
	}
	
	/** 
	 * Tests the case that the init function gets a wrong parameters
	 * the expected result is to throw IllegalArgumentException
	 * @param the output file
	 */
	public void wrongInitialization(PrintWriter file){ 
		String testResult = null; 
		try{
			//creates the arguments with an arguments such that p!=2q+1
			BigInteger p = new BigInteger("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15" +
					  "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
					  "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330" +
					  "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
					  "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
					  "CF9DE5384E71B81C0AC4DFFE0C10E64F", 16);
			BigInteger q = new BigInteger("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB", 16);
			BigInteger g = new BigInteger("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA" +
					  "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
					  "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EF" +
					  "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
					  "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
					  "81BC087F2A7065B384B890D3191F2BFA", 16);
			ZpGroupParams params = new ZpGroupParams(q, g, p);
			//init the object with the wrong arguments
			((CryptoPpDlogZpSafePrime) dlog).init(params);
			
		//the expected result of this test is IllegalArgumentException
		}catch (IllegalArgumentException e){
			testResult = "Success: The expected exception \"IllegalArgumentException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalArgumentException\" was thrown";
		}
		
		//writes the result to the file
		file.println(dlog.getGroupType() + "," + provider + ",Wront Initialization,Wrong behavior,,," + testResult);
	}
	
	/** 
	 * Tests the case that the argument to a dlog function is not match the dlog type
	 * the expected result is to throw IllegalArgumentException
	 * @param the output file
	 */	
	protected void wrongArgumentType(PrintWriter file){
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			//creates an elliptic curve dlog in order to get an element of elliptic curve type
			BcDlogECFp dlogTemp = new BcDlogECFp();
			dlogTemp.init("P-521");
			//gets the generator of the created dlog
			GroupElement element = dlogTemp.getGenerator();
			
			//init the tested DlogZp object
			ZpGroupParams params = new ZpGroupParams(new BigInteger("22"), new BigInteger("3"), new BigInteger("11"));
			((CryptoPpDlogZpSafePrime) dlog).init(params);
			
			//calls the exponentiate function with the elliptic curve element
			dlog.exponentiate(element, new BigInteger("3"));
			
		//the expected result of this test is IllegalArgumentException	
		}catch(IllegalArgumentException e){
			testResult = "Success: The expected exception \"IllegalArgumentException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalArgumentException\" was thrown";
		}
		
		//writes the result to the file
		file.println(dlog.getGroupType() + "," + provider + ",Wrong argument type,Wrong behavior,,," + testResult);
	}
	
	/** 
	 * Tests the case that the argument to the constructor of a dlog element is not legal element value
	 * the expected result is to throw IllegalArgumentException
	 * @param the output file
	 */	
	protected void wrongElementInput(PrintWriter file){
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			//init the tested dlog
			ZpGroupParams params = new ZpGroupParams(new BigInteger("11"), new BigInteger("3"), new BigInteger("23"));
			((CryptoPpDlogZpSafePrime) dlog).init(params);
			
			//create an element with value 5 which is no quadratic residue of this dlog
			((CryptoPpDlogZpSafePrime) dlog).getElement(new BigInteger("5"), true);
			
		//the expected result of this test is IllegalArgumentException
		}catch(IllegalArgumentException e){
			testResult = "Success: The expected exception \"IllegalArgumentException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalArgumentException\" was thrown";
		}
		
		//writes the result to the file
		file.println(dlog.getGroupType() + "," + provider + ",wrong Element Input,Wrong behavior,,," + testResult);
		
	}
	
	protected void conversionsTest(PrintWriter file){
		String testResult = null; //the test result. initialized to failure
		try {
			//init the tested dlog
			((CryptoPpDlogZpSafePrime) dlog).init(1024);
			
			//converts the generator to byte array
			GroupElement generator= dlog.getGenerator();
			byte[] gBytes = dlog.convertGroupElementToByteArray(generator);
			//converts back to the generator
			GroupElement backToGenerator = dlog.convertByteArrayToGroupElement(gBytes);
			
			//checks if the converted element is equal to the generator
			if (generator.equals(backToGenerator)){
				testResult = "Success: The conversions from GroupElement to byte array and vice versa succeeded";
			} else {
				testResult = "Failure: The conversions from GroupElement to byte array and vice versa failed";
			}
		} catch (UnInitializedException e) {
			// shouldn't occur since the dlog is initialized
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//writes the result to the file
		file.println(dlog.getGroupType() + "," + provider + ",conversionsTest,Test vector,,," + testResult);
	}
}
