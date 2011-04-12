/**
 * 
 */
package edu.biu.scapi.tests;

import java.util.Vector;

import edu.biu.scapi.primitives.crypto.hash.bc.BcSHA1;
import edu.biu.scapi.primitives.crypto.hash.bc.BcSHA224;
import edu.biu.scapi.primitives.crypto.hash.bc.BcSHA256;
import edu.biu.scapi.primitives.crypto.hash.bc.BcSHA384;
import edu.biu.scapi.primitives.crypto.hash.bc.BcSHA512;
import edu.biu.scapi.primitives.crypto.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.primitives.crypto.prf.Hmac;
import edu.biu.scapi.primitives.crypto.prf.bc.BcAES;
import edu.biu.scapi.primitives.crypto.prf.bc.BcTripleDES;
import edu.biu.scapi.tests.primitives.AESTest;
import edu.biu.scapi.tests.primitives.HmacTest;
import edu.biu.scapi.tests.primitives.SHA1Test;
import edu.biu.scapi.tests.primitives.SHA224Test;
import edu.biu.scapi.tests.primitives.SHA256Test;
import edu.biu.scapi.tests.primitives.SHA384Test;
import edu.biu.scapi.tests.primitives.SHA512Test;
import edu.biu.scapi.tests.primitives.TripleDESTest;
import edu.biu.scapi.tools.Factories.PrfFactory;

/** 
 * @author LabTest
 */
public class RegressionTest {
	
	private Vector<Test> tests;
	
	/**
	 * 
	 */
	public RegressionTest() {
		tests = new Vector<Test>();
		
		fillTestVector();
	}
	
	/**
	 * 
	 * runRegressionTest
	 * @param outputFileName
	 */
	public void runRegressionTest(String outputFileName) {
		
		tests = new Vector<Test>();
		fillTestVector();
		
		int numOfTests = tests.size();
		
		for(int i=0; i<numOfTests;i++){
			
			tests.get(i).runTest();
		}
	}

	/**
	 * 
	 * compareVersions
	 * @param fileNameVer1
	 * @param fileNameVer2
	 */
	public void compareVersions(String fileNameVer1, String fileNameVer2) {
		
	}

	/**
	 * 
	 * fillTestVector
	 */
	private void fillTestVector() {
		
		tests.add(new AESTest(new BcAES()));
		tests.add(new TripleDESTest(new BcTripleDES()));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA224)", "BC")));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA384)", "BC")));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA512)", "BC")));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA256)", "BC")));
		tests.add(new SHA1Test(new BcSHA1()));
		tests.add(new SHA1Test(new CryptoPpSHA1()));
		tests.add(new SHA224Test(new BcSHA224()));
		tests.add(new SHA256Test(new BcSHA256()));
		tests.add(new SHA384Test(new BcSHA384()));
		tests.add(new SHA512Test( new BcSHA512()));
	}
}