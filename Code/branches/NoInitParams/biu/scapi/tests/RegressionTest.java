package edu.biu.scapi.tests;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Vector;
import java.util.logging.Level;


import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.generals.Logging;

import edu.biu.scapi.primitives.dlog.bc.BcDlogECFp;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECFp;
import edu.biu.scapi.primitives.hash.bc.BcSHA1;
import edu.biu.scapi.primitives.hash.bc.BcSHA256;
import edu.biu.scapi.primitives.hash.bc.BcSHA384;
import edu.biu.scapi.primitives.hash.bc.BcSHA512;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA224;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA384;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA512;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.bc.BcKdfISO18033;
import edu.biu.scapi.primitives.prf.Hmac;
import edu.biu.scapi.primitives.prf.IteratedPrfVarying;
import edu.biu.scapi.primitives.prf.LubyRackoffPrpFromPrfVarying;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.primitives.prf.bc.BcTripleDES;
import edu.biu.scapi.tests.primitives.AESTest;
import edu.biu.scapi.tests.primitives.CryptoPpRabinTest;
import edu.biu.scapi.tests.primitives.DlogECF2mTest;
import edu.biu.scapi.tests.primitives.DlogECFpTest;
import edu.biu.scapi.tests.primitives.DlogZpTest;
import edu.biu.scapi.tests.primitives.EvaluationHashFunctionTest;
import edu.biu.scapi.tests.primitives.HkdfTest;
import edu.biu.scapi.tests.primitives.IteratedPrfVaryingTest;
import edu.biu.scapi.tests.primitives.KdfIso18033Test;
import edu.biu.scapi.tests.primitives.LubyRackoffPrpFromPrfVaryingTest;
import edu.biu.scapi.tests.primitives.RC4Test;
import edu.biu.scapi.tests.primitives.ScRSATest;
import edu.biu.scapi.tests.primitives.CryptoPpRSATest;
import edu.biu.scapi.tests.primitives.HmacTest;
import edu.biu.scapi.tests.primitives.SHA1Test;
import edu.biu.scapi.tests.primitives.SHA224Test;
import edu.biu.scapi.tests.primitives.SHA256Test;
import edu.biu.scapi.tests.primitives.SHA384Test;
import edu.biu.scapi.tests.primitives.SHA512Test;
import edu.biu.scapi.tests.primitives.TripleDESTest;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;
import edu.biu.scapi.tools.Factories.KdfFactory;
import edu.biu.scapi.tools.Factories.PrfFactory;
import edu.biu.scapi.tools.Factories.PrgFactory;
import edu.biu.scapi.tools.Factories.TrapdoorPermutationFactory;
import edu.biu.scapi.tools.Factories.UniversalHashFactory;

/** 
 * @author LabTest
 */
public class RegressionTest {
	
	private Vector<Test> tests;
	
	/**
	 * @throws FactoriesException 
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
		
		
		
		try {
			PrintWriter file= new PrintWriter(outputFileName);
			file.println("Algorithm,Provider,Computation,Type of test,Input,Output,Result");
		
			int numOfTests = tests.size();
			
			for(int i=0; i<numOfTests;i++){
				tests.get(i).wrongBehavior(file);
				tests.get(i).testVector(file);	
			}
			file.close();
		} catch (IOException e) {
			Logging.getLogger().log(Level.INFO, "can't open the given output file", e);
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
	 * @throws FactoriesException 
	 */

	private void fillTestVector() {
		
		try{	
		tests.add(new AESTest(new BcAES()));
		tests.add(new TripleDESTest(new BcTripleDES()));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA224)", "BC")));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA384)", "BC")));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA512)", "BC")));
		tests.add(new HmacTest((Hmac) PrfFactory.getInstance().getObject("HMac(SHA256)", "BC")));
		tests.add(new IteratedPrfVaryingTest(new IteratedPrfVarying("HMac(SHA224)")));
		tests.add(new LubyRackoffPrpFromPrfVaryingTest(new LubyRackoffPrpFromPrfVarying("IteratedPrfVarying(HMac(SHA224))")));
		tests.add(new SHA1Test(new BcSHA1()));
		tests.add(new SHA1Test(new CryptoPpSHA1()));
		tests.add(new SHA224Test(CryptographicHashFactory.getInstance().getObject("SHA224", "BC")));
		tests.add(new SHA224Test(new CryptoPpSHA224()));
		tests.add(new SHA256Test(new BcSHA256()));
		tests.add(new SHA256Test(CryptographicHashFactory.getInstance().getObject("SHA256", "CryptoPP")));
		tests.add(new SHA384Test(new BcSHA384()));
		tests.add(new SHA384Test(new CryptoPpSHA384()));
		tests.add(new SHA512Test(new BcSHA512()));
		tests.add(new SHA512Test(new CryptoPpSHA512()));
		tests.add(new EvaluationHashFunctionTest(UniversalHashFactory.getInstance().getObject("EvaluationHash")));
		tests.add(new CryptoPpRSATest(TrapdoorPermutationFactory.getInstance().getObject("RSA", "CryptoPP")));
		tests.add(new ScRSATest(TrapdoorPermutationFactory.getInstance().getObject("RSA", "Scapi")));
		tests.add(new CryptoPpRabinTest(TrapdoorPermutationFactory.getInstance().getObject("Rabin", "CryptoPP")));
		tests.add(new HkdfTest(new HKDF("HMac(SHA256)")));
		tests.add(new KdfIso18033Test(new BcKdfISO18033("SHA1")));
		tests.add(new RC4Test(PrgFactory.getInstance().getObject("RC4")));
		tests.add(new DlogZpTest(DlogGroupFactory.getInstance().getObject("DlogZpSafePrime", "CryptoPP")));
		tests.add(new DlogECFpTest(new MiraclDlogECFp()));
		tests.add(new DlogECFpTest(new BcDlogECFp()));
		tests.add(new DlogECF2mTest(DlogGroupFactory.getInstance().getObject("DlogECF2m", "BC")));
		tests.add(new DlogECF2mTest(DlogGroupFactory.getInstance().getObject("DlogECF2m", "Miracl")));
		tests.add(new HkdfTest(KdfFactory.getInstance().getObject("HKDF(HMac(SHA256))", "Scapi")));
		
		}catch (FactoriesException e) {
			Logging.getLogger().log(Level.INFO, "Some tests could not be run. Exception:", e);
		}
		
	}
}