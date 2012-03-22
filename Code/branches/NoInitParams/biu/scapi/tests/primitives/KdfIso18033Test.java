package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;

/**
 * This class tests the performance and correctness of any implemented Hkdf algorithm.
 * The test vectors are taken http://www.shoup.net/iso/std6.pdf
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class KdfIso18033Test extends KdfTest{
	public KdfIso18033Test(KeyDerivationFunction kdf) {
		super(kdf);
		
		//these tests are for kdf/SHA1
		byte[] input = Hex.decode("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741"
                            	+ "52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
		byte[] output = Hex.decode("5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca9"
                            	+ "75bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263c"
                            	+ "fccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e"
                            	+ "7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04");
		addData(input, output, null, null, output.length);//input
		
		byte[] input1 = Hex.decode("d6e168c5f256a2dcff7ef12facd390f393c7a88d");
		byte[] output1 = Hex.decode("c325ebbb41a82551d5d0ad4834870a05ef3918c8caae38873f07dc" +
									"a43127a4dee36a6ca5970f6c06926037de7df79c4915d83ff705821d" +
									"2c46a1fa7bb81b73e27176feb7fd3a45e40b843f1aaebccb1ef4fa7e" +
									"e3b9b491a342f43eaaa435efded41e0a3a6ec2eff1f2ed95");
		addData(input1, output1, null, null, output1.length);//input
		
		byte[] input2 = Hex.decode("069d9155d26654c441c91826d46ab4d432126fa767");
		byte[] output2 = Hex.decode("2eb9b894759c38f14fb1edd042403b8966f3e26375" +
									"d7bfbd19eb146797dcd7c180bde240ff8c2216e583" +
									"490af019af5dec1d9c510bf4cff105118c48b53cfd" +
									"13484932b77f8f816e64dc39705763edd6f74c2e4e" +
									"0b1ebcbd934da6e2a0295e95f50f50044050547e6b" +
									"d5b1");
		addData(input2, output2, null, null, output2.length);//input
	}
	
	/**
	 * Runs all the required wrong behavior tests for kdf. 
	 * KdfIso18033 doesn't need the tests of unInited and badCasting since it has no init function
	 */
	public void wrongBehavior(PrintWriter file) {
		//calls the wrong behavior functions
		wrongOffset(file); //case that the given offset to the generateKey function is not in the range
		wrongLength(file);  //case that the given length to the generateKey function is not in the range
	}
}
