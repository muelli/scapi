package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.prf.Hmac;

/**
 * This class tests the performance and correctness of any implemented HMac algorithm.
 * The test vectors are taken from http://datatracker.ietf.org/doc/rfc4231/?include_text=1
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class HmacTest extends PrfTest {
	/**
	 * Sets the given Hmac object, adds data for the test vector.
	 */
	public HmacTest(Hmac hmac) {
		super(hmac);
		
		//HMAC/SHA224
		if(hmac.getBlockSize()==28){
			
			
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
			
			addData(Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),//input
					Hex.decode("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"),//output
					Hex.decode("4a656665"));//key
			
			addData(Hex.decode("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"),//input
					Hex.decode("3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"),//output
					Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));//key
			
			
			byte[] input = {0, 0, 0, 0, 0, 0, 0, 0, 60, 1};
			byte[] output = {-70, -84, -105, -88, -98, -28, -35, -49, 36, 44, 110, 37, 115, -98, 102, 123, 68, 102, -10, 60, 69, 31, 115, 106, 110, 84, 101, 54};
			
			//this test is for the test of IteratedPrfVarying - we need the output of the first iteration
			addData(input,//input
					output,//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
			
			byte[] input2 = {0, 0, 0, 0, 0, 0, 0, 0, 60, 2};
			byte[] output2 = {120, -115, -42, 41, 5, 74, 125, 110, -70, 29, 40, -89, 23, -42, -33, 126, 86, 75, -45, 8, 8, 125, 9, 7, -7, -116, -70, 17};
			
			//this test is for the test of IteratedPrfVarying - we need the output of the second iteration
			addData(input2,//input
					output2,//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
			
			byte[] input3 = {0, 0, 0, 0, 0, 0, 0, 0, 60, 3};
			byte[] output3 = {65, 51, 37, -63, 51, 113, 28, 120, -71, 115, 20, -19, 35, -16, -84, 31, 21, -26, 114, -105, -13, 93, -73, -7, -58, -77, -124, 102};
			
			//this test is for the test of IteratedPrfVarying - we need the output of the third iteration
			addData(input3,//input
					output3,//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
			
		}

		
		//HMAC/SHA256
		if(hmac.getBlockSize()==32){
			
				addData(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),//input
					Hex.decode("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),//output
					Hex.decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));//key
		
			
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
			
			addData(Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),//input
					Hex.decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),//output
					Hex.decode("4a656665"));//key
			
			addData(Hex.decode("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"),//input
					Hex.decode("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),//output
					Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));//key
			
		}

		//HMAC/SHA384
		if(hmac.getBlockSize()==48){
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
		
			addData(Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),//input
					Hex.decode("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"),//output
					Hex.decode("4a656665"));//key

			addData(Hex.decode("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"),//input
					Hex.decode("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"),//output
					Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));//key
			
		}
		
		
		//HMAC/SHA512
		if(hmac.getBlockSize()==64){
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
		
			
			addData(Hex.decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),//input
					Hex.decode("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),//output
					Hex.decode("4a656665"));//key
			
			addData(Hex.decode("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"),//input
					Hex.decode("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"),//output
					Hex.decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));//key
			
		}

	}
	
	
}