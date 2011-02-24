/** 
 * class CommunicationSetup:
 * 
 * An application requesting from CommunicationSetup to prepare for communication needs to provide the following information as input:
 *   •	The list of parties to connect to. As a convention, we will set the first party in the list to be the requesting party, that is, 
 * 		the party represented by the application. 
 *   •	The security level required. We assume the same security level for all connections for a given protocol. This may change.
 * 		We define four levels of security: a) plain, b) encrypted, c) authenticated d) encrypted and authenticated.
 *   •	Which type of connecting success is required.
 *   •	Which Key Exchange Protocol to use.
 *   •	What encryption and/or mac algorithm to use.
 *   •	A time-out specifying how long to wait for connections to be established and secured.
 * 
 * CommunicationSetup implements the org.apache.commons.exec.TimeoutObserver interface. 
 * This interface supplies a mechanism for notifying classes that a timeout has arrived. 
 */

package edu.biu.scapi.comm;


import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import org.apache.commons.exec.TimeoutObserver;
import org.apache.commons.exec.Watchdog;


public class CommunicationSetup implements TimeoutObserver{
	private boolean bTimedOut = false;
	private List<Party> listOfParties;
	private EstablishedConnections establishedConnections;
	private KeyExchangeProtocol keyExchangeProtocol;
	private ConnectivitySuccessVerifier connectivitySuccessVerifier;
	private SecurityLevel securityLevel;
	private ListeningThread listeningThread;
	private Vector<SecuringConnectionThread> threadsVector;
	private Map<InetSocketAddress,KeyExchangeOutput> keyExchangeMap;

	/** 
	 * The main function of the class. This function is also the only public function in the class. An application that wants to use
	 * the communication layer will call this function in order to prepare for communication after providing the required parameters. 
	 * This function initiates the creation of the final actual socket connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.
	 * @param listOfParties - the original list of parties to connect to
	 * @param keyExchange - the key exchange algorithm protocol to use after a channel is connected
	 * @param securityLevel - the required security level for all the connections. E.g Plain, encrypted, authenticated or secured.
	 * @param successLevel - the ConnectivitySuccessVerifier algorithm to use
	 * @param timeOut - the maximum amount of time we allow for the connection stage.
	 * @return - true is the success function has succeeded and false otherwise.
	 */
	public boolean prepareForCommunication(List<Party> listOfParties,
			KeyExchangeProtocol keyExchange, SecurityLevel securityLevel,
			ConnectivitySuccessVerifier successLevel, long timeOut) {
		
		//set parameters
		this.listOfParties = listOfParties;
		keyExchangeProtocol = keyExchange;
		this.securityLevel = securityLevel;
		connectivitySuccessVerifier = successLevel;
		
		establishedConnections = new EstablishedConnections();
		
		//initialize the threadVector and the map of the key exchange outputs
		threadsVector = new Vector<SecuringConnectionThread>();
		keyExchangeMap = new HashMap<InetSocketAddress,KeyExchangeOutput>();
		
		//start the watch dog with timeout
		Watchdog watchdog = new Watchdog(timeOut);
		//add this instance as the observer in order to receive the event of time out.
		watchdog.addTimeoutObserver(this);
		
		watchdog.start();
		
		//establish connections.
		establishAndSecureConnections();
		
		//verify connection
		verifyConnectingStatus();
		
		//run success function
		if(runSuccessAlgo()==false){
			//remove connections from the list of established connections
			return false;
		}
		
		//remove all connections with not READY state
		establishedConnections.removeNotReadyConnections();
		
		//update the security level for each connection
		setSecurityLevel();
		
		return true;
		
	}


	/**
	 * 
	 * establishAndSecureConnections : using the SecuringConnectionThread and the ListeningThread we connect the parties via sockets.
	 * 								   We either connect by initiating a connection or by listening to incoming connection requests.
	 * @return
	 */
	private Map<InetSocketAddress, Channel> establishAndSecureConnections() {
		
		//Create an iterator to go over the list of parties 
		Iterator<Party> itr = listOfParties.iterator();
		Party firstParty = null;
		Party party;
		
		//temp map
		Map<InetAddress, SecuringConnectionThread> localMapforListeningThread = new HashMap<InetAddress, SecuringConnectionThread>();
		
		//the first party is me. Other parties identity will be compared with this party
		if(itr.hasNext()){
			
			firstParty = itr.next();
		}
		
		//go over the elements of the list of parties
		while(itr.hasNext()){
			
			//get the next party in the list.
			party = itr.next();
			
			//create an InetSocketAddress
			InetSocketAddress inetSocketAdd = new InetSocketAddress(party.getIpAddress(), party.getPort());
			//create a channel for this party
			PlainChannel channel = new PlainTCPChannel(inetSocketAdd);
			//set to NOT_INIT state
			channel.setState(State.NOT_INIT);
			//add to the established connection object
			establishedConnections.addConnection(channel, inetSocketAdd);
			
			//create a key exchange output to pass to the SecringConnectionThread
			KeyExchangeOutput keyExchangeOutput = new KeyExchangeOutput();
			
			//add the key exchange output to the map
			keyExchangeMap.put(inetSocketAdd, keyExchangeOutput);
			
			
			//UPWARD connection
			if(firstParty.compareTo(party)>0){
				
				//create a new SecuringConnectionThread 
				SecuringConnectionThread scThread = new SecuringConnectionThread(channel, party.getIpAddress(), party.getPort(), true, keyExchangeProtocol, keyExchangeOutput);
				
				//add to the thread vector
				threadsVector.add(scThread);
				
				//start the thread
				scThread.start();
								
			}
			else{ //DOWN connection
				
				
				//create a new SecuringConnectionThread 
				SecuringConnectionThread scThread = new SecuringConnectionThread(channel, party.getIpAddress(), party.getPort(), false, keyExchangeProtocol, keyExchangeOutput);
				
				//add to the thread vector
				threadsVector.add(scThread);
				
				//add thread to the local vector so the listening thread can start the securing thread.
				localMapforListeningThread.put(party.getIpAddress(), scThread);
				
			}
		}
		
		if(localMapforListeningThread.size()>0){//there are down connections need to listen to connections using the listeningThread
			//send information to the listening thread
			listeningThread = new ListeningThread(localMapforListeningThread, firstParty.getPort());
			listeningThread.start();
		}
		return establishedConnections.getConnections();
	}

	/**
	 *  
	 * verifyConnectingStatus : This function goal is to serve as a barrier. It is called from the prepareForCommunication function. The idea
	 * 							is to let all the threads finish running before proceeding. 
	 */ 
	private void verifyConnectingStatus() {

		//while the thread has not been stopped and no all the channels are connected
		while(bTimedOut==false && establishedConnections.areAllConnected()==false ){
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	/** 
	 * 
	 * runSuccessAlgo : Runs the success algorithm. 
	 * @return : true if the connections in the connections in the establishedConnections and possibly connections of the other parties 
	 * 			 has succeeded in terms of the success algorithm. Otherwise, false. If the success has failed all the connections of the 
	 * 			 establishedConnections are removed
	 */
	private boolean runSuccessAlgo() {

		//call the relevant success algorithm
		return connectivitySuccessVerifier.hasSucceded(establishedConnections, listOfParties);
	}

	/**
	 * 
	 * setSecurityLevel : In this function we decorate the channels to suit the requested security level. If the required security level
	 * 					  is plain, no decoration is needed. For authenticated we decorate the channel by an authenticated channel. for encrypted, we 
	 * 					  decorate with encrypted channel. For secured, we decorated with both authenticated and encrypted channel.
	 * 
	 *  Note:			  The decorated channel has a different pointer in memory, thus we need to put the newly decorated channel in the map
	 *  				  and removing the plain channel from the map. Since we iterate on the map, we cannot remove and add in the middle of 
	 *  				  iteration ( we would get the ConcurrentModificationException exception) and thus we create a temporary map with the decorated channels and at the end clear the map and add all
	 *  				  the decorated channels.
	 */
	private void setSecurityLevel() {
		
		//Set the security level only if the security level is not plain. If it is plain there is nothing to decorate
		
		//create a temp map since if we change the main map in the middle of iterations we will get the exception ConcurrentModificationException 
		Map<InetSocketAddress,Channel> tempConnections = new HashMap<InetSocketAddress,Channel>();  
		
		if(securityLevel!=SecurityLevel.PLAIN){
		
			InetSocketAddress localInetSocketAddress = null;
			Set<InetSocketAddress> set = establishedConnections.getConnections().keySet();
	
			//go over the addresses of the established connections map
		    Iterator<InetSocketAddress> itr = set.iterator();
		    while (itr.hasNext()) {
		    	
		    	//get the channel's address
		    	localInetSocketAddress = itr.next();
		    	
		    	//get the channel from the collection
		    	Channel ch = establishedConnections.getConnection(localInetSocketAddress);
		    	
		    	//remove the channel and save it for decoration
		    	//Channel ch = establishedConnections.removeConnection(localInetSocketAddress);
		    	
		    	//get the keyExchange output
		    	KeyExchangeOutput keyExchangeOutput = keyExchangeMap.get(localInetSocketAddress) ;
		    	
		    	//decorate the channel
		    	switch(securityLevel){
		    		case ENCRYPTED :{
		    			
		    			//create an encrypted channel
		    			EncryptedChannel encChannel = new EncryptedChannel(ch, keyExchangeOutput.getEncKey());
		    			//establishedConnections.addConnection(encChannel, localInetSocketAddress);
		    			tempConnections.put(localInetSocketAddress,encChannel);
		    			break;
		    		}
		    		case AUTHENTICATED : {
		    			
		    			//create an authenticated channel
		    			AuthenticatedChannel authenChannel = new AuthenticatedChannel(ch, keyExchangeOutput.getMacKey());
		    			//establishedConnections.addConnection(authenChannel, localInetSocketAddress);
		    			tempConnections.put(localInetSocketAddress, authenChannel);
		    			break;
		    		}
		    		case SECURE : {
		    			
		    			//decorate with authentication and then with encryption - order is important for security
		    			AuthenticatedChannel authenChannel = new AuthenticatedChannel(ch, keyExchangeOutput.getMacKey());
		    			EncryptedChannel secureChannel = new EncryptedChannel(authenChannel, keyExchangeOutput.getEncKey());
		    			
		    			//establishedConnections.addConnection(secureChannel, localInetSocketAddress);
		    			tempConnections.put(localInetSocketAddress, secureChannel);
		    			break;
		    			
		    		}
		    	}		    		
		    }
		    
		    establishedConnections.getConnections().clear();
		    establishedConnections.getConnections().putAll(tempConnections);
		}	
	}

	/**
	 * timeoutOccured : An event called if the timeout has passed. This is called by the infrastructure of the watchdog and the fact that
	 * 					this class is also an observer.
	 */
	public void timeoutOccured(Watchdog w) {

		System.out.println("Timeout accured");
		
		//timeout has passed set the flag
		bTimedOut = true;
		
		//stop all threads in the vector and the listening thread
		for(int i=0; i< threadsVector.size(); i++){
			
			//get a thread from the vector of threads
			SecuringConnectionThread thread = threadsVector.elementAt(i);
			
			//sets the flag of the thread to stopped. This will make the run function of the thread to terminate if it has not finished yet.
			thread.stopConnecting();
			
		}	
		
		//further stop the listening thread if it still runs. Similarly, it sets the flag of the listening thread to stopped.
		if(listeningThread!=null)
			listeningThread.stopConnecting();
	}
	
	public Map<InetSocketAddress, Channel> getConnections(){
		return establishedConnections.getConnections();
		
	}
}