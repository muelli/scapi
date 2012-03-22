package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.logging.Level;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class tests the performance and correctness of any implemented elliptic curve DlogGroup over Fp algorithm.
 * The test vectors are taken from http://tools.ietf.org/html/rfc5114#appendix-A
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class DlogECFpTest extends DlogECTest{
	
	public DlogECFpTest(DlogGroup dlog) {
		super(dlog);
		
		//192-bit Random ECP Group
		String params = "P-192";
		BigInteger exponent = new BigInteger("631F95BB4A67632C9C476EEE9AB695AB240A0499307FCF62", 16);
		BigInteger xElementA = new BigInteger("CD46489ECFD6C105E7B3D32566E2B122E249ABAADD870612", 16);
		BigInteger yElementA = new BigInteger("68887B4877DF51DD4DC3D6FD11F0A26F8FD3844317916E9A", 16);
		BigInteger xExpectedOutput = new BigInteger("AD420182633F8526BFE954ACDA376F05E5FF4F837F54FEBE", 16);
		BigInteger yExpectedOutput = new BigInteger("4371545ED772A59741D0EDA32C671112B7FDDD51461FCF32", 16);
		addData(params, exponent, xElementA, yElementA, xExpectedOutput, yExpectedOutput);
		
		BigInteger x = new BigInteger("323FA3169D8E9C6593F59476BC142000AB5BE0E249C43426", 16);
		BigInteger xElementB = new BigInteger("519A121680E0045466BA21DF2EEE47F5973B500577EF13D5", 16);
		BigInteger yElementB = new BigInteger("FF613AB4D64CEE3A20875BDB10F953F6B30CA072C60AA57F", 16);
		addData(params, x, xElementB, yElementB, xExpectedOutput, yExpectedOutput);
		
		//224-bit Random ECP Group
		String params1 = "P-224";
		BigInteger y1 = new BigInteger("AC3B1ADD3D9770E6F6A708EE9F3B8E0AB3B480E9F27F85C88B5E6D18", 16);
		BigInteger xElementA1 = new BigInteger("49DFEF309F81488C304CFF5AB3EE5A2154367DC7833150E0A51F3EEB", 16);
		BigInteger yElementA1 = new BigInteger("4F2B5EE45762C4F654C1A0C67F54CF88B016B51BCE3D7C228D57ADB4", 16);
		BigInteger xOutput1 = new BigInteger("52272F50F46F4EDC9151569092F46DF2D96ECC3B6DC1714A4EA949FA", 16);
		BigInteger yOutput1 = new BigInteger("5F30C6AA36DDC403C0ACB712BB88F1763C3046F6D919BD9C524322BF", 16);
		addData(params1, y1, xElementA1, yElementA1, xOutput1, yOutput1);
		
		BigInteger x1 = new BigInteger("B558EB6C288DA707BBB4F8FBAE2AB9E9CB62E3BC5C7573E22E26D37F", 16);
		BigInteger xElementB1 = new BigInteger("6B3AC96A8D0CDE6A5599BE8032EDF10C162D0A8AD219506DCD42A207", 16);
		BigInteger yElementB1 = new BigInteger("D491BE99C213A7D1CA3706DEBFE305F361AFCBB33E2609C8B1618AD5", 16);
		addData(params1, x1, xElementB1, yElementB1, xOutput1, yOutput1);
		
		//256-bit Random ECP Group
		String params2 = "P-256";
		BigInteger y2 = new BigInteger("2CE1788EC197E096DB95A200CC0AB26A19CE6BCCAD562B8EEE1B593761CF7F41", 16);
		BigInteger xElementA2 = new BigInteger("2AF502F3BE8952F2C9B5A8D4160D09E97165BE50BC42AE4A5E8D3B4BA83AEB15", 16);
		BigInteger yElementA2 = new BigInteger("EB0FAF4CA986C4D38681A0F9872D79D56795BD4BFF6E6DE3C0F5015ECE5EFD85", 16);
		BigInteger xOutput2 = new BigInteger("DD0F5396219D1EA393310412D19A08F1F5811E9DC8EC8EEA7F80D21C820C2788", 16);
		BigInteger yOutput2 = new BigInteger("0357DCCD4C804D0D8D33AA42B848834AA5605F9AB0D37239A115BBB647936F50", 16);
		addData(params2, y2, xElementA2, yElementA2, xOutput2, yOutput2);
		

		BigInteger x2 = new BigInteger("814264145F2F56F2E96A8E337A1284993FAF432A5ABCE59E867B7291D507A3AF", 16);
		BigInteger xElementB2 = new BigInteger("B120DE4AA36492795346E8DE6C2C8646AE06AAEA279FA775B3AB0715F6CE51B0", 16);
		BigInteger yElementB2 = new BigInteger("9F1B7EECE20D7B5ED8EC685FA3F071D83727027092A8411385C34DDE5708B2B6", 16);
		addData(params2, x2, xElementB2, yElementB2, xOutput2, yOutput2);
		
		//384-bit Random ECP Group
		String params3 = "P-384";
		BigInteger y3 = new BigInteger("52D1791FDB4B70F89C0F00D456C2F7023B6125262C36A7DF1F80231121CCE3D39BE52E00C194A4132C4A6C768BCD94D2", 16);
		BigInteger xElementA3 = new BigInteger("793148F1787634D5DA4C6D9074417D05E057AB62F82054D10EE6B0403D6279547E6A8EA9D1FD77427D016FE27A8B8C66", 16);
		BigInteger yElementA3 = new BigInteger("C6C41294331D23E6F480F4FB4CD40504C947392E94F4C3F06B8F398BB29E42368F7A685923DE3B67BACED214A1A1D128", 16);
		BigInteger xOutput3 = new BigInteger("5EA1FC4AF7256D2055981B110575E0A8CAE53160137D904C59D926EB1B8456E427AA8A4540884C37DE159A58028ABC0E", 16);
		BigInteger yOutput3 = new BigInteger("0CC59E4B046414A81C8A3BDFDCA92526C48769DD8D3127CAA99B3632D1913942DE362EAFAA962379374D9F3F066841CA", 16);
		addData(params3, y3, xElementA3, yElementA3, xOutput3, yOutput3);
		

		BigInteger x3 = new BigInteger("D27335EA71664AF244DD14E9FD1260715DFD8A7965571C48D709EE7A7962A156D706A90CBCB5DF2986F05FEADB9376F1", 16);
		BigInteger xElementB3 = new BigInteger("5CD42AB9C41B5347F74B8D4EFB708B3D5B36DB65915359B44ABC17647B6B9999789D72A84865AE2F223F12B5A1ABC120", 16);
		BigInteger yElementB3 = new BigInteger("E171458FEAA939AAA3A8BFAC46B404BD8F6D5B348C0FA4D80CECA16356CA933240BDE8723415A8ECE035B0EDF36755DE", 16);
		addData(params3, x3, xElementB3, yElementB3, xOutput3, yOutput3);
		
		
		//521-bit Random ECP Group
		String params4 = "P-521";
		BigInteger y4 = new BigInteger("00CEE3480D8645A17D249F2776D28BAE616952D1791FDB4B70F7C3378732AA1B22928448BCD1DC2496D4" +
									   "35B01048066EBE4F72903C361B1A9DC1193DC2C9D0891B96", 16);
		BigInteger xElementA4 = new BigInteger("01EBB34DD75721ABF8ADC9DBED17889CBB9765D90A7C60F2CEF007BB0F2B26E14881FD4442E689D61CB2" +
											   "DD046EE30E3FFD20F9A45BBDF6413D583A2DBF59924FD35C", 16);
		BigInteger yElementA4 = new BigInteger("00F6B632D194C0388E22D8437E558C552AE195ADFD153F92D74908351B2F8C4EDA94EDB0916D1B53C020" +
											   "B5EECAED1A5FC38A233E4830587BB2EE3489B3B42A5A86A4", 16);
		BigInteger xOutput4 = new BigInteger("00CDEA89621CFA46B132F9E4CFE2261CDE2D4368EB5656634C7CC98C7A00CDE54ED1866A0DD3E6126C9D" +
											 "2F845DAFF82CEB1DA08F5D87521BB0EBECA77911169C20CC", 16);
		BigInteger yOutput4 = new BigInteger("00F9A71641029B7FC1A808AD07CD4861E868614B865AFBECAB1F2BD4D8B55EBCB5E3A53143CEB2C511B1" +
											 "AE0AF5AC827F60F2FD872565AC5CA0A164038FE980A7E4BD", 16);
		addData(params4, y4, xElementA4, yElementA4, xOutput4, yOutput4);
		

		BigInteger x4 = new BigInteger("0113F82DA825735E3D97276683B2B74277BAD27335EA71664AF2430CC4F33459B9669EE78B3FFB9B8683" +
									   "015D344DCBFEF6FB9AF4C6C470BE254516CD3C1A1FB47362", 16);
		BigInteger xElementB4 = new BigInteger("010EBFAFC6E85E08D24BFFFCC1A4511DB0E634BEEB1B6DEC8C5939AE44766201AF6200430BA97C8AC6A0" +
											   "E9F08B33CE7E9FEEB5BA4EE5E0D81510C24295B8A08D0235", 16);
		BigInteger yElementB4 = new BigInteger("00A4A6EC300DF9E257B0372B5E7ABFEF093436719A77887EBB0B18CF8099B9F4212B6E30A1419C18E029" +
											   "D36863CC9D448F4DBA4D2A0E60711BE572915FBD4FEF2695", 16);
		
		addData(params4, x4, xElementB4, yElementB4, xOutput4, yOutput4);
	}
	
	protected void conversionsTest(PrintWriter file){
		String testResult = null; //the test result. initialized to failure
		try {
			//init the tested dlog
			((DlogECFp) dlog).init("P-192");
			
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
	
	/** 
	 * Tests the case that the argument to the constructor of a dlog element is not legal element value
	 * the expected result is to throw IllegalArgumentException
	 * @param the output file
	 */	
	protected void wrongElementInput(PrintWriter file){
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			//init the tested object as elliptic curve of type B-163
			((DlogEllipticCurve) dlog).init("P-192");
			
			//create an element which is not valid to this dlog
			((DlogEllipticCurve) dlog).getElement(new BigInteger("5"), new BigInteger("5"));
			
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
}
