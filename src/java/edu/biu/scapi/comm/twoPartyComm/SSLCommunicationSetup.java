/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/

package edu.biu.scapi.comm.twoPartyComm;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.generals.Logging;

/**
 * This class implements a communication between two parties using SSL sockets.<p>
 * It derives the SocketCommunicationSetup class since the implementation is equal except the channel type.
 * This class creates an {@link SSLSocketChannel} while the SocketCommunicationSetup creates a {@link PlainTCPSocketChannel}.<p>
 * 
 * In order to create an sslSocket you should have an {@link SSLContext} which should be loaded with the key store and trust store. 
 * The keyStore contains the certificate that should be sent to the other party, we hardcoded the name as "scapiKeystore".
 * The trustStore contains the certificate that should be received from the other party, we hardcoded the name as "scapiCacerts".
 * This loading is done one in the constructor of this class and is passed to the {@link SSLSocketListenerThread} and to each {@link SSLSocketChannel}. This factory is used to send the certificate of this application.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SSLCommunicationSetup extends SocketCommunicationSetup{
	
	private SSLContext sc;	//Loaded with the keyStore and trustStore and used to get the SSLSocketFactory and SSLServerSocketFactory from.
	
	/**
	 * Constructor that gets the data of both parties and the password to the keyStore and trustStore.
	 * @param me The data of the current application.
	 * @param party The data of the other application.
	 * @param storePassword The password to the keyStore and trustStore
	 * @throws DuplicatePartyException
	 */
	public SSLCommunicationSetup(PartyData me, PartyData party, String storePass) throws DuplicatePartyException {
		super(me, party);
		
		//Creating the SSL Context to get the socket factories from.
		try {
			
			//Loading the trust store containing the certificate that should be received from the other party.
			KeyStore trustStore = KeyStore.getInstance("JKS");
			trustStore.load(new FileInputStream("scapiCacerts.jks"), storePass.toCharArray());
	        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
	        tmf.init(trustStore);
	         
	        //Loading the key store containing the certificate that should be sent to the other party.
	        KeyStore keyStore = KeyStore.getInstance("JKS");
	        keyStore.load(new FileInputStream("scapiKeystore.jks"), storePass.toCharArray());
	        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	        kmf.init(keyStore, storePass.toCharArray());
	         
	        //Create the SSL context and initialize it with the created key store and trust store.
	        sc = SSLContext.getInstance("TLSv1.2");
	        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
		
		} catch (IOException e) {
			Logging.getLogger().log(Level.FINEST, e.toString());    
		} catch (KeyStoreException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString()); 
		} catch (NoSuchAlgorithmException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString()); 
		} catch (CertificateException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString()); 
		} catch (KeyManagementException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString()); 
		} catch (UnrecoverableKeyException e) {
			Logging.getLogger().log(Level.SEVERE, e.toString()); 
		}
	}
	
	@Override
	protected void establishAndSecureConnections(String[] connectionsIds) {
		//Create an InetSocketAddress of the other party.
		InetSocketAddress inetSocketAdd = new InetSocketAddress(other.getIpAddress(), other.getPort());
		
		int size = connectionsIds.length;
		//Create an array to hold the created channels.
		SSLSocketChannel[] channels = new SSLSocketChannel[size];
		
		//Create the number of channels as requested.
		for (int i=0; i<size; i++){
			//Create an ssl channel.
			channels[i] = new SSLSocketChannel(inetSocketAdd, sc.getSocketFactory());
			
			//Set to NOT_INIT state.
			channels[i].setState(PlainTCPSocketChannel.State.NOT_INIT);
			//Add to the established connection object.
			establishedConnections.addConnection(connectionsIds[i], channels[i]);
		}
		
		//Create a listening thread with the created channels.
		//The listening thread receives calls from the other party and set the creates sockets as the receiveSocket of the channels.
		listeningThread = new SSLSocketListenerThread(channels, me, other.getIpAddress(), sc.getServerSocketFactory());
		listeningThread.start();
		
		//Start the connections between me to the other party.
		connect(channels);
	}

}
