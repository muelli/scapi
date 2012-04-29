/**
 * 
 */
package edu.biu.scapi.anonymousForums;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import edu.biu.scapi.anonymousForums.ForumUser.GroupElementPair;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.DlogZp;
import edu.biu.scapi.primitives.dlog.ECParameterSpec;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.bc.BcDlogECFp;
import edu.biu.scapi.primitives.dlog.miracl.ECFpPointMiracl;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECFp;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;

import org.bouncycastle.util.BigIntegers;

/**
 * @author Cryptography and Computer Security Research Group Department of
 *         Computer Science Bar-Ilan University (Yael Ejgenberg)
 * 
 */
public class ForumUser {

	DlogGroup dlogGroup;
	BigInteger q; // Once we get the dlogGroup in the constructor keep the order
					// in variable q, since it is used so many times.
	CryptographicHash hashH; // Need to check upon construction that the size of
								// the output of hashH is smaller than number of
								// bits of q.
	CryptographicHash hashG;
	int d; // degree of the polynomial
	int id; // the id of this user, a number between 0 and n-1
	int n; // number of possible users
	AnonymousForumLongTermPublicKey longTermPublicKey;
	AnonymousForumLongTermPrivateKey longTermPrivateKey;

	AnonymousForumSpecificPublicKey forumPublicKey;
	AnonymousForumSpecificPrivateKey forumPrivateKey;
	// Array that holds the forum public key of each participant, including me.
	// Therefore, it should hold that allParticipantsPublicKey[id] ==
	// this.forumPublicKey
	AnonymousForumSpecificPublicKey[] allParticipantsPublicKey;
	SecureRandom random = new SecureRandom();

	public ForumUser(DlogGroup dlogGroup, CryptographicHash hashH,
			CryptographicHash hashG, int d, int id, int n, SecureRandom random)
			throws UnInitializedException {
		super();
		this.dlogGroup = dlogGroup;
		this.q = dlogGroup.getOrder();
		this.hashH = hashH;
		this.hashG = hashG;
		this.d = d;
		this.id = id;
		this.n = n;
		this.random = random;
	}

	class GroupElementPair {
		GroupElement first;
		GroupElement second;

		public GroupElementPair(GroupElement first, GroupElement second) {
			this.first = first;
			this.second = second;
		}

		public GroupElement getFirst() {
			return first;
		}

		public GroupElement getSecond() {
			return second;
		}

		public void release() {
			first.release();
			second.release();
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			result = prime * result + ((first == null) ? 0 : first.hashCode());
			result = prime * result
					+ ((second == null) ? 0 : second.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			GroupElementPair other = (GroupElementPair) obj;
			if (!getOuterType().equals(other.getOuterType()))
				return false;
			if (first == null) {
				if (other.first != null)
					return false;
			} else if (!first.equals(other.first))
				return false;
			if (second == null) {
				if (other.second != null)
					return false;
			} else if (!second.equals(other.second))
				return false;
			if(this.first.equals(other.first) && this.second.equals(other.second))
				return true;
			return false;
		}

		private ForumUser getOuterType() {
			return ForumUser.this;
		}
		
		
	}

	void generateLongTermKeys() throws IllegalArgumentException,
			UnInitializedException {
		// First generate and set long term public/private keys
		// Choose alpha in Zq:
		BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		BigInteger alpha = BigIntegers.createRandomInRange(BigInteger.ZERO,
				qMinusOne, random);
		// Calculate h
		GroupElement h = dlogGroup
				.exponentiate(dlogGroup.getGenerator(), alpha);
		longTermPublicKey = new AnonymousForumLongTermPublicKey(h);
		longTermPrivateKey = new AnonymousForumLongTermPrivateKey(alpha);
	}

	void generateSpecificForumKeys() throws UnInitializedException {
		// Generate the private key.
		// Put the coefficients in a vector of size d:
		Vector<BigInteger> coeff = new Vector<BigInteger>(d + 1);
		coeff.add(0, longTermPrivateKey.alpha);
		BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		for (int j = 1; j <= d; j++) {
			coeff.add(j, BigIntegers.createRandomInRange(BigInteger.ZERO,
					qMinusOne, random));
		}
		// Create d random exponents:
		Vector<BigInteger> randomExp = new Vector<BigInteger>(d);
		for (int j = 0; j < d; j++) {
			randomExp.add(j, BigIntegers.createRandomInRange(BigInteger.ZERO,
					qMinusOne, random));
		}
		// Set the private key.
		forumPrivateKey = new AnonymousForumSpecificPrivateKey(coeff, randomExp);

		// Generate the public key.

		Vector<GroupElementPair> publicCoeff = new Vector<GroupElementPair>(d);
		for (int j = 0; j < d; j++) {
			GroupElement first = dlogGroup.exponentiate(dlogGroup.getGenerator(), randomExp.elementAt(j));
			GroupElement second = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(longTermPublicKey.getH(), randomExp.elementAt(j)),
																  dlogGroup.exponentiate(dlogGroup.getGenerator(), coeff.elementAt(j + 1)));

			publicCoeff.add(j, new GroupElementPair(first, second));
		}

		forumPublicKey = new AnonymousForumSpecificPublicKey(longTermPublicKey.getH(), publicCoeff);
	}


	AnonymousForumLongTermPublicKey getLongtermPublicKey() {
		return longTermPublicKey;
	}

	AnonymousForumSpecificPublicKey getForumSpecificPublicKey() {
		return forumPublicKey;
	}

	void setAllParticipantsPublicKeys(
			AnonymousForumSpecificPublicKey[] allParticipantsPublicKey) {
		this.allParticipantsPublicKey = allParticipantsPublicKey;
	}

	boolean checkAlgo(byte[] msg) throws UnInitializedException{
		boolean works = false;
		// First compute s = hashH(msg):
		byte[] sArray = new byte[hashH.getHashedMsgSize()];
		hashH.update(msg, 0, msg.length);
		hashH.hashFinal(sArray, 0);
		//System.out.println("Finished calculating hashH(s)");
		// Then evaluate polynomial(s) = a0*s^0 + a1*s^1 + a2 *s^3+...+ad*s^d:
		BigInteger s = new BigInteger(sArray);
		BigInteger polynomialEval = evaluatePolynomial(forumPrivateKey, s);
		//System.out.println("Finished evaluating polynom");
		GroupElementPair elGamalResult = calculateElGamalOfPolynomialEval(
				allParticipantsPublicKey[id], s, polynomialEval);

		//System.out.println("Finished calculateElGamalOfPolynomialEval " + n	+ " times");

		Vector<BigInteger> randomExponents = forumPrivateKey.getRandomExponents();

		BigInteger rTag = BigInteger.valueOf(0);
		for (int j = 1; j <= d; j++) {
			BigInteger temp = randomExponents.get(j - 1).multiply(s.pow(j));
			rTag = rTag.add(temp);
		}
		rTag = rTag.mod(q);
		//Compare (u,v) to (g^rTag, h^rTag)
		GroupElement gExpRtag = dlogGroup.exponentiate(dlogGroup.getGenerator(), rTag);
		GroupElement hExpRtag = dlogGroup.exponentiate(allParticipantsPublicKey[id].getH(), rTag);
		if(elGamalResult.first.equals(gExpRtag) && elGamalResult.second.equals(hExpRtag))
			works = true;
		
		return works;
	}
	PostedMessage post(byte[] msg) throws UnInitializedException {
		// First compute s = hashH(msg):
		byte[] sArray = new byte[hashH.getHashedMsgSize()];
		hashH.update(msg, 0, msg.length);
		hashH.hashFinal(sArray, 0);
		//System.out.println("Finished calculating hashH(s)");
		// Then evaluate polynomial(s) = a0*s^0 + a1*s^1 + a2 *s^3+...+ad*s^d:
		BigInteger s = new BigInteger(sArray);
		BigInteger polynomialEval = evaluatePolynomial(forumPrivateKey, s);
		//System.out.println("Finished evaluating polynom");
		// Calculate the El Gamal encryption of polynomial(s) using the public
		// key for each participant of the forum:
		GroupElementPair[] cipherArray = new GroupElementPair[n];
		for (int k = 0; k < n; k++) {
			cipherArray[k] = calculateElGamalOfPolynomialEval(allParticipantsPublicKey[k], s, polynomialEval);
		}
		//System.out.println("Finished calculateElGamalOfPolynomialEval " + n	+ " times");
				

		// Calculate first prover msg for this user:
		BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		BigInteger ro = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		GroupElement a = dlogGroup.exponentiate(dlogGroup.getGenerator(), ro);
		GroupElement b = dlogGroup.exponentiate(longTermPublicKey.getH(), ro);

		// aKByteArray and bKByteArray are utility arrays where we keep these
		// group elements in their byte[]
		// representation for later use when calculating the challenge.
		byte[][] aKByteArray = new byte[n][];
		byte[][] bKByteArray = new byte[n][];
		// We already have calculated A and B for this user, so we keep their
		// byte[] representation already from here in the
		// respective arrays. This way they won't be missed when calculating the
		// challenge.
		aKByteArray[id] = dlogGroup.convertGroupElementToByteArray(a);
		bKByteArray[id] = dlogGroup.convertGroupElementToByteArray(b);
		BigInteger[] allEs = new BigInteger[n]; // The size of this array is n, even though we won't keep this user's e in it.
		
		// Prepare all simulated proofs:
		ZKProof[] arrayOfProofs = new ZKProof[n];
		for (int k = 0; k < n; k++) {
			// skip my user
			if (k == id)
				continue;
			BigInteger z = BigIntegers.createRandomInRange(BigInteger.ZERO,	qMinusOne, random);
			BigInteger e = BigIntegers.createRandomInRange(BigInteger.ZERO,	qMinusOne, random);
			// Save this e for later use when calculating the challenge.
			allEs[k] = e;
			BigInteger qMinusE = q.subtract(e);
			GroupElement aK = dlogGroup.multiplyGroupElements(dlogGroup.exponentiate(dlogGroup.getGenerator(), z),
															  dlogGroup.exponentiate(cipherArray[k].first, qMinusE));
			aKByteArray[k] = dlogGroup.convertGroupElementToByteArray(aK);
			GroupElement hkToPowerOfZk = dlogGroup.exponentiate(allParticipantsPublicKey[k].getH(), z);
			GroupElement bK = dlogGroup.multiplyGroupElements(hkToPowerOfZk,
															  dlogGroup.exponentiate(cipherArray[k].second, qMinusE));
			// hkToPowerOfZk.release();
			bKByteArray[k] = dlogGroup.convertGroupElementToByteArray(bK);
			arrayOfProofs[k] = new ZKProof(new GroupElementPair(aK, bK), e, z);
		}
		//System.out.println("Finished preparing all simulated proofs for " + n	+ " users");
		byte[] hashGResult = computeHashG(cipherArray, aKByteArray,	bKByteArray, polynomialEval);

		// Compute challenge
		BigInteger challenge = computeChallenge(new BigInteger(hashGResult), allEs);
		//System.out.println("Finish computeChallenge");
		// Complete real proof. We have calculated the first prover msg (a,b)
		// and the challenge. Now calculate the second prover message
		BigInteger z = completeRealProof(s, ro, challenge);
		arrayOfProofs[id] = new ZKProof(new GroupElementPair(a, b), challenge, z);
		//System.out.println("Finish computeChallenge");
		return new PostedMessage(msg, polynomialEval, arrayOfProofs);
	}

	byte[] computeHashG(GroupElementPair[] cipherArray, byte[][] aKByteArray,
			byte[][] bKByteArray, BigInteger polynomialEval)
			throws UnInitializedException {
		// Compute hashG e = hashG((h1|u1|v1|A1|B1)|...|((hn|un|vn|An|Bn)|polynomialEval)
		// For each participant convert all the group elements mentioned above
		// (hk, uk, vk, Ak,Bk) to byte[] and the byte[]
		// to the hash function. At then end call doFinal to hash on all the
		// inputed byte[]s.
		for (int k = 0; k < n; k++) {
			// Convert the group element h of this participant's public key to
			// byte[].
			// And add it to the hash function.
			byte[] hArray = dlogGroup.convertGroupElementToByteArray(allParticipantsPublicKey[k].getH());
			hashG.update(hArray, 0, hArray.length);
			// Convert ck.first to byte []
			// And add it to the hash function.
			byte[] cFirst = dlogGroup.convertGroupElementToByteArray(cipherArray[k].first);
			hashG.update(cFirst, 0, cFirst.length);
			// Convert ck.second to byte []
			// And add it to the hash function.
			byte[] cSnd = dlogGroup.convertGroupElementToByteArray(cipherArray[k].second);
			hashG.update(cSnd, 0, cSnd.length);
			// Add the ak element to the hash function.
			hashG.update(aKByteArray[k], 0, aKByteArray[k].length);
			// Add the bk element to the hash function.
			hashG.update(bKByteArray[k], 0, bKByteArray[k].length);
		}

		hashG.update(polynomialEval.toByteArray(), 0, polynomialEval.toByteArray().length);
		// Finish the calculation of the hash:
		byte[] hashGResult = new byte[hashG.getHashedMsgSize()];
		hashG.hashFinal(hashGResult, 0);

		return hashGResult;
	}

	BigInteger computeChallenge(BigInteger hashGResult, BigInteger[] allEs)
			throws UnInitializedException {
		BigInteger sum = BigInteger.valueOf(0);
		for (int k = 0; k < n; k++) {
			// Skip this user, according to what is stipulated in the algorithm.
			if (k == id)
				continue;
			sum = sum.add(allEs[k]);
		}
		sum = sum.mod(q);

		// Does it return a new BigInteger? Does it return the right value?
		return hashGResult.subtract(sum).mod(q);
	}

	BigInteger completeRealProof(BigInteger s, BigInteger ro,
			BigInteger challenge) throws UnInitializedException {
		Vector<BigInteger> randomExponents = forumPrivateKey.getRandomExponents();

		BigInteger rTag = BigInteger.valueOf(0);
		for (int j = 1; j <= d; j++) {
			//BigInteger temp = randomExponents.get(j - 1).multiply(s.pow(j));
			rTag = rTag.add(randomExponents.get(j - 1).multiply(s.pow(j)));
		}
		rTag = rTag.mod(q);

		BigInteger z = ro.add(challenge.multiply(rTag));

		return z.mod(q);
		
	}

	public static byte[] concatAll(byte[] first, byte[]... rest) {
		int totalLength = first.length;
		for (byte[] array : rest) {
			totalLength += array.length;
		}
		byte[] result = Arrays.copyOf(first, totalLength);
		int offset = first.length;
		for (byte[] array : rest) {
			System.arraycopy(array, 0, result, offset, array.length);
			offset += array.length;
		}
		return result;
	}

	GroupElementPair calculateElGamalOfPolynomialEval(AnonymousForumSpecificPublicKey forumPublicKey, BigInteger s,	BigInteger polynomialEval) throws UnInitializedException {
		GroupElement u = null;
		GroupElement v = null;
		GroupElement h = forumPublicKey.getH();
		// Iterate over all the publicCoeff of public key in order to build an
		// array of ui and an array of vi:
		GroupElement[] uis = new GroupElement[d];
		GroupElement[] vis = new GroupElement[d];
		Iterator<GroupElementPair> itr = forumPublicKey.getCoefficients().iterator();
		int i = 0;
		while (itr.hasNext()) {
			GroupElementPair pair = (GroupElementPair) itr.next();
			uis[i] = pair.getFirst();
			vis[i] = pair.getSecond();
			i++;
		}
		// Build si array
		BigInteger[] sis = new BigInteger[d];
		for (int j = 0; j < d; j++) {
			BigInteger jPlusOne = BigInteger.valueOf(j + 1);
			sis[j] = s.modPow(jPlusOne, q);
		}
		// Calculate u = (u1^s)*(u1^(s^2))*...(ud^(s^d))
		//For the moment calculate the product of the exponentiations without optimizations
		//u = dlogGroup.simultaneousMultipleExponentiations(uis, sis);
		u = dlogGroup.exponentiate(uis[0], sis[0]);
		for(int t = 1; t <d; t++){
			u = dlogGroup.multiplyGroupElements(u, dlogGroup.exponentiate(uis[t], sis[t]));
		}
		
		
		//GroupElement vMult = dlogGroup.simultaneousMultipleExponentiations(vis,	sis);
		GroupElement vMult = dlogGroup.exponentiate(vis[0], sis[0]);
		for(int t = 1; t <d; t++){
			vMult = dlogGroup.multiplyGroupElements(vMult, dlogGroup.exponentiate(vis[t], sis[t]));
		}
		
		// Release uis and vis
		/*
		 * for(int j = 0; j < d; j++){ uis[j].release(); vis[j].release(); }
		 */
		GroupElement vTag = dlogGroup.multiplyGroupElements(h, vMult);
		GroupElement gExpPolynomialEval = dlogGroup.exponentiate(dlogGroup.getGenerator(), polynomialEval);
		GroupElement inverseGExpPolynomialEval = dlogGroup.getInverse(gExpPolynomialEval);
		v = dlogGroup.multiplyGroupElements(vTag, inverseGExpPolynomialEval);
		// vTag.release();
		return new GroupElementPair(u, v);
	}

	BigInteger evaluatePolynomial(AnonymousForumSpecificPrivateKey forumPrivateKey, BigInteger s) {
		BigInteger result = new BigInteger("0");
		for (int j = 0; j <= d; j++) {
			// Calculate aj*s^j, where aj =
			// forumPrivateKey.getCoefficients().elementAt(j)
			BigInteger nom = forumPrivateKey.getCoefficients().elementAt(j).multiply(s.pow(j));
			result = result.add(nom);
		}
		// Calculate result mod q (so that it stays in Zq)
		result = result.mod(q);
		return result;
	}

	boolean verifyPost(PostedMessage postedMsg) throws UnInitializedException {
		boolean verified = true;
		// First compute s = hashH(msg):
		byte[] sArray = new byte[hashH.getHashedMsgSize()];
		hashH.update(postedMsg.getMsg(), 0, postedMsg.getMsg().length);
		hashH.hashFinal(sArray, 0);
		BigInteger s = new BigInteger(sArray);
		//System.out.println("In verifyPost. Finsished hashH(s)");
		// Calculate the El Gamal encryption of polynomial(s) using the public
		// key for each participant of the forum:
		GroupElementPair[] cipherArray = new GroupElementPair[n];
		for (int k = 0; k < n; k++) {
			// System.out.println("About to calculateElGamalOfPolynomialEval, k = "
			// + k);
			cipherArray[k] = calculateElGamalOfPolynomialEval(allParticipantsPublicKey[k], s, postedMsg.getPolynomialEval());
		}
		// Get As and Bs:
		ZKProof[] arrayOfProofs = postedMsg.getArrayOfProofs();
		byte[][] aKByteArray = new byte[n][];
		byte[][] bKByteArray = new byte[n][];
		for (int k = 0; k < n; k++) {
			aKByteArray[k] = dlogGroup.convertGroupElementToByteArray(arrayOfProofs[k].getFirstProverMsg().getFirst());
			bKByteArray[k] = dlogGroup.convertGroupElementToByteArray(arrayOfProofs[k].getFirstProverMsg().getSecond());
		}
		// Verify the proof:
		byte[] hashGResult = computeHashG(cipherArray, aKByteArray,
				bKByteArray, postedMsg.getPolynomialEval());

		// Release cipherArray:
		/*
		 * for(int k = 0; k < n; k++){ cipherArray[k].release(); }
		 */
		BigInteger e = new BigInteger(hashGResult);

		BigInteger sumOfEs = BigInteger.valueOf(0);
		for (int k = 0; k < n; k++) {
			sumOfEs = sumOfEs.add(arrayOfProofs[k].getChallengeMsg());
		}
		e = e.mod(q);
		sumOfEs = sumOfEs.mod(q);
		if (e.compareTo(sumOfEs) != 0) {
			verified = false;
			return verified;
		}
		// For every k = 1..n, verify that g^zk = Ak*uk^ek and h^zk = Bk * vk^ek
		verified = true;
		for (int k = 0; k < n; k++) {
			GroupElement gExpZk = dlogGroup.exponentiate(dlogGroup.getGenerator(), arrayOfProofs[k].secondProverMsg);
			GroupElement aKuKExpEk = dlogGroup.multiplyGroupElements(arrayOfProofs[k].getFirstProverMsg().getFirst(), 
																	 dlogGroup.exponentiate(cipherArray[k].first, arrayOfProofs[k].challengeMsg));
			if (!gExpZk.equals(aKuKExpEk)) {
				//System.out.println("gExpZk not equals aKuKExpEk at k = " + k);
				//ECFpPointMiracl element = (ECFpPointMiracl) gExpZk;
				//System.out.println("gExpZk.x = " + element.getX());
				//System.out.println("gExpZk.y = " + element.getY());

				verified = false;
				break;
			}
			GroupElement hExpZk = dlogGroup.exponentiate(allParticipantsPublicKey[k].getH(), arrayOfProofs[k].secondProverMsg);
			GroupElement bKvKExpEk = dlogGroup.multiplyGroupElements(arrayOfProofs[k].getFirstProverMsg().getSecond(), 
																	 dlogGroup.exponentiate(cipherArray[k].second, arrayOfProofs[k].challengeMsg));
			if (!hExpZk.equals(bKvKExpEk)) {
				//System.out.println("hExpZk not equals bKuKExpEk at k = " + k);
				//ECFpPointMiracl element = (ECFpPointMiracl) hExpZk;
				//System.out.println("hExpZk.x = " + element.getX());
				//System.out.println("hExpZk.y = " + element.getY());
				verified = false;
				break;
			}

		}
		return verified;
	}

	/*
	 * NumOfTests = 1 DlogGroup = DlogECFp dlogProvider = Miracl
	 * AlgorithmParameterSpec = ECParameterSpec hashH = SHA224 hashHProvider =
	 * BC hashG = SHA224 hashProvider = BC polynomialDegree = 10 numOfusers = 10
	 */
	
	static AnonymousForumConfig[] readConfigFile() {
		AnonymousForumConfig[] configArray = null;
		try {
			BufferedReader bf = new BufferedReader(
					new FileReader(
							"C:\\work\\LAST_Project\\SDK\\Code\\JavaSrc\\edu\\biu\\scapi\\anonymousForums\\AnonymousConfig.ini"));
			String line;
			String[] tokens;
			line = bf.readLine();
			int numOfTests = 0;
			if (line.startsWith("NumOfTests")) {
				tokens = line.split("=");
				String tok = tokens[1].trim();
				numOfTests = new Integer(tok).intValue();
			}
			configArray = new AnonymousForumConfig[numOfTests];
			int i = 0;
			String dlogGroup = null;
			String dlogProvider = null;
			String algorithmParameterSpec = null;
			String hashH = null;
			String hashHProvider = null;
			String hashG = null;
			String hashGProvider = null;
			String polynomialDegree = null;
			String numOfusers = null;

			int count = 0;
			while ((line = bf.readLine()) != null) {
				// System.out.println(line);
				if (line.startsWith("dlogGroup")) {
					tokens = line.split("=");
					dlogGroup = tokens[1].trim();
				} else if (line.startsWith("dlogProvider")) {
					tokens = line.split("=");
					dlogProvider = tokens[1].trim();
				} else if (line.startsWith("algorithmParameterSpec")) {
					tokens = line.split("=");
					algorithmParameterSpec = tokens[1].trim();
				} else if (line.startsWith("hashH")) {
					tokens = line.split("=");
					hashH = tokens[1].trim();
				} else if (line.startsWith("providerHashH")) {
					tokens = line.split("=");
					hashHProvider = tokens[1].trim();
				} else if (line.startsWith("hashG")) {
					tokens = line.split("=");
					hashG = tokens[1].trim();
				} else if (line.startsWith("providerHashG")) {
					tokens = line.split("=");
					hashGProvider = tokens[1].trim();
				} else if (line.startsWith("polynomialDegree")) {
					tokens = line.split("=");
					polynomialDegree = tokens[1].trim();
				} else if (line.startsWith("numOfusers")) {
					tokens = line.split("=");
					numOfusers = tokens[1].trim();
				}
				count++;
				if (count == 9) {
					configArray[i] = new AnonymousForumConfig(dlogGroup, dlogProvider, algorithmParameterSpec, hashH, hashHProvider, 
															  hashG, hashGProvider,	polynomialDegree, numOfusers);
					i++;
					count = 0;
				}
			}

			bf.close();
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
		return configArray;

	}

	void writeTestResult(AnonymousForumConfig config, long usersCreationTime,
			long msgPostingTime, long msgVerifyingTime)
			throws FileNotFoundException {
		PrintWriter out = new PrintWriter(
				"C:\\work\\LAST_Project\\SDK\\Code\\JavaSrc\\edu\\biu\\scapi\\anonymousForums\\testResults.csv");
		String str = config.dlogGroup + "," + config.dlogProvider + ","
				+ config.algorithmParameterSpec + "," + config.hashH + ","
				+ config.hashHProvider;
		str += "," + config.hashG + "," + config.hashGProvider + ","
				+ config.polynomialDegree + "," + config.numOfusers;
		out.println(str);
	}

	static String runTest(AnonymousForumConfig config)
			throws FactoriesException, IllegalArgumentException, IOException,
			UnInitializedException {
		int n = new Integer(config.numOfusers).intValue();
		int d = new Integer(config.polynomialDegree).intValue();
		DlogGroup dlogGroup = DlogGroupFactory.getInstance().getObject(config.dlogGroup+"("+config.algorithmParameterSpec+")", config.dlogProvider);
		// DlogGroup dlogGroup = new MiraclDlogECFp();
		// DlogGroup dlogGroup = new BcDlogECFp();
		// dlogGroup.init(new ECParameterSpec("P-224"));
		// dlogGroup.init(new ECParameterSpec("B-233"));
		

		// CryptographicHash hashH = new BcSHA224();
		// CryptographicHash hashG = new BcSHA224();
		CryptographicHash hashH = CryptographicHashFactory.getInstance().getObject(config.hashH, config.hashHProvider);
		CryptographicHash hashG = CryptographicHashFactory.getInstance().getObject(config.hashG, config.hashGProvider);

		ForumUser[] arrayOfUsers = new ForumUser[n];
		AnonymousForumLongTermPublicKey[] allLongTermPublicKeys = new AnonymousForumLongTermPublicKey[n];
		AnonymousForumSpecificPublicKey[] allSpecificForumPublicKeys = new AnonymousForumSpecificPublicKey[n];
		System.out.println("Creating " + n	+ " users and generating their set of keys");
		Date startCreation = new Date();
		for (int k = 0; k < n; k++) {
			// Create user number k
			ForumUser fU = new ForumUser(dlogGroup, hashH, hashG, d, k, n,
					new SecureRandom());
			// Generate user's long term public key and specific forum public
			// key
			fU.generateLongTermKeys();
			fU.generateSpecificForumKeys();
			// Keep track of the user
			arrayOfUsers[k] = fU;
			// Keep track of this user's public keys
			allLongTermPublicKeys[k] = fU.getLongtermPublicKey();
			allSpecificForumPublicKeys[k] = fU.getForumSpecificPublicKey();
		}
		Date endCreation = new Date();
		long usersCreationTime = (endCreation.getTime() - startCreation
				.getTime());
		//System.out.println("Finished creating users and their keys. It took "	+ usersCreationTime + " ms to create users with keys");
		// Publish all keys to all users of forum:
		//System.out.println("Publish all keys to all users of forum.");
		for (int k = 0; k < n; k++) {
			arrayOfUsers[k].setAllParticipantsPublicKeys(allSpecificForumPublicKeys);
		}

		
		// Now the actual test!!
		// Have user #5 post a message and user #7 verify it:
		String myMessage = new String("I'm posting a message in this forum. I hope it works!");
		//System.out.println(myMessage);
		
				
		
		Date startPost = new Date();
		PostedMessage postedMsg = arrayOfUsers[3].post(myMessage.getBytes());
		Date endPost = new Date();
		long postingTime = (endPost.getTime() - startPost.getTime());
		//System.out.println("Finished posting message. It took " + postingTime + " ms to post");
		//System.out.println("The posted message is: " + new String(postedMsg.getMsg()));

		Date startVerify = new Date();
		boolean isTrue = arrayOfUsers[1].verifyPost(postedMsg);
		Date endVerify = new Date();
		String success;
		if (isTrue){
			success = "Verified!";
			System.out.println("Verified!");
		}
		else{
			success = "Failed...";
			System.out.println("Failed...");
		}
		long verifyingTime = (endVerify.getTime() - startVerify.getTime());
		//System.out.println("Finished verifying message. It took " + verifyingTime + " ms to verify");

		String str = config.dlogGroup + "," + config.dlogProvider + ","	+ config.algorithmParameterSpec + "," + config.hashH + ","	+ config.hashHProvider;
		str += "," + config.hashG + "," + config.hashGProvider + "," + config.polynomialDegree + "," + config.numOfusers;
		str += "," + usersCreationTime + "," + postingTime + "," + verifyingTime + "," + success;

		return str;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {

			// Create n = 10 users.
			// The degree of the polynomial d = 3
			// DlogGroup is Elliptic Curve is p224
			// hash H is sHA224
			// hash G is sHA224

			// Get parameters from config file:
			AnonymousForumConfig[] config = readConfigFile();
			Date now = new Date();
			String testName = "C:\\work\\LAST_Project\\SDK\\Code\\JavaSrc\\edu\\biu\\scapi\\anonymousForums\\testResults.csv";
			PrintWriter out = new PrintWriter(testName);
			out.println("dlogGroup,dlogProvide,algorithmParameterSpec,hashH,hashHProvider,hashG,hashGProvider,polynomialDegree,numOfusers,usersCreationTime, postingTime, verifyingTime, Result");
			out.flush();
			String result = null;
			for (int i = 0; i < config.length; i++) {
				result = runTest(config[i]);
				out.println(result);
				System.out.println(result);
			}
			out.flush();
			out.close();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnInitializedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
