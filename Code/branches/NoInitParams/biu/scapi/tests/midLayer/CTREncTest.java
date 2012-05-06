package edu.biu.scapi.tests.midLayer;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;

import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScCTREncRandomIV;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.SymKeyGenParameterSpec;
import edu.biu.scapi.primitives.prf.bc.BcAES;

public class CTREncTest {

	public static void main(String[] args){

		/*
		ScCTREncRandomIV enc = new ScCTREncRandomIV(new BcAES());

		SymKeyGenParameterSpec keySpec = new SymKeyGenParameterSpec(128);
		SecretKey secretKey = null;
		SecureRandom random = new SecureRandom();
		byte[] IV = new byte[16]; 
		random.nextBytes(IV);
		System.out.print("IV: ");
		for(int i = 0; i < 16; i++){
			System.out.print(IV[i] + " ");
		}
		try {
			secretKey = enc.generateKey(keySpec );
		} catch (InvalidParameterSpecException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}

		//init the encryptor with the new secret key
		try {
			enc.init(secretKey);
		} catch (InvalidKeyException e1) {

			e1.printStackTrace();
		}


		
		//Open the file for reading
		try {
			System.out.println("Encrypting file");
			BufferedReader br = new BufferedReader(new FileReader("C://work//LAST_Project//SDK//Docs//SDD_docs//shortFileToEncrypt.txt"));
			PrintWriter outEnc = new PrintWriter("C://work//LAST_Project//SDK//Docs//SDD_docs//shortFileToEncrypt_encrypted.txt");

			
		//outEnc.println(IVString );    
		
			String thisLine;
			byte buf[];
			ByteArrayOutputStream f	= new ByteArrayOutputStream();
			//Read full file to encrypt into ByteArrayOutputStream
			while ((thisLine = br.readLine()) != null) { // while loop begins here  
    			buf = thisLine.getBytes(); 
				f.write(buf);
			}
			br.close();

			//prepare to encrypt the whole file in one step
			BasicPlaintext plaintext= new BasicPlaintext(f.toByteArray());
			IVCiphertext cipher;
			try {
				//encrypt the whole file in one step. use predefined iv
				cipher = (IVCiphertext) enc.encrypt(plaintext, IV);
				//print resulting cipher as string to output file
				outEnc.print(new String(cipher.getCipher()));
			} catch (UnInitializedException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		outEnc.flush();
		outEnc.close();
	} // end try
	catch (IOException e) {
		System.err.println("Error: " + e);
	}
		
		try {
			System.out.println("Decrypting file");
			BufferedReader br = new BufferedReader(new FileReader("C://work//LAST_Project//SDK//Docs//SDD_docs//shortFileToEncrypt_encrypted.txt"));
			PrintWriter outEnc = new PrintWriter("C://work//LAST_Project//SDK//Docs//SDD_docs//shortFileToEncrypt_decrypted.txt");
			String thisLine;
	
			byte[] buf;
			ByteArrayOutputStream f	= new ByteArrayOutputStream();
			while ((thisLine = br.readLine()) != null) { // while loop begins here  
				buf = thisLine.getBytes(); 
				f.write(buf);
			}
			br.close();



			IVCiphertext cipher = new IVCiphertext(f.toByteArray(), IV);
			BasicPlaintext plaintext;
			try {
				plaintext = (BasicPlaintext) enc.decrypt(cipher);
				outEnc.print(new String(plaintext.getText()));
			} catch (UnInitializedException e) {
				e.printStackTrace();
			}

			br.close();
			outEnc.flush();
			outEnc.close();
		} // end try
		catch (IOException e) {
			System.err.println("Error: " + e);
		}


		*/
		//"SCAPI Non-Interactive Crypto Mid-Layer R&D Group Software Design Description Written by Yael Ejgenberg Approved by Created 10 April 2011 Modified 10 April 2011"
	    String text = "I want to encrypt this sentence. I don't know how to make it long enough. It is suppossed to be of at least one block size";
		System.out.println("the plaintext is: " + text);


		ScCTREncRandomIV enc = null;
		enc = new ScCTREncRandomIV(new BcAES());
		
		
		SymKeyGenParameterSpec keySpec = new SymKeyGenParameterSpec(128);
		SecretKey secretKey = null;
		try {
			secretKey = enc.generateKey(keySpec );
		} catch (InvalidParameterSpecException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}

		//init the encryptor with the new secret key
		try {
			enc.setKey(secretKey);
		} catch (InvalidKeyException e1) {

			e1.printStackTrace();
		}

		Plaintext plain = new BasicPlaintext(text.getBytes());
		IVCiphertext cipher;
		
		SecureRandom random = new SecureRandom();
		byte[] IV = new byte[16]; 
		random.nextBytes(IV);
		//cipher = (IVCiphertext) enc.encrypt(plain, IV);
		cipher = (IVCiphertext) enc.encrypt(plain);
		System.out.println("The cipher is: " + new String(cipher.getBytes()));
		BasicPlaintext revertedPlain = (BasicPlaintext) enc.decrypt(cipher);
		System.out.println("The reverted string is: " + new String(revertedPlain.getText()));
		


	}
		 
	}

