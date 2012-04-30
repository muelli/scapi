package edu.biu.scapi.anonymousForums;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Label;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;

public class AnonymousForumApp extends JPanel {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 2693836791142829119L;
	static ForumUser forum;
	static AnonymousForumLongTermPublicKey[] allLongTermPublicKeys;
	static AnonymousForumSpecificPublicKey[] allSpecificForumPublicKeys;
	static int n = 5;
	private static String specificFuromPublicKeysDir = System.getProperty("java.class.path").toString().split(";")[0]+"\\specificForumPublicKeys";
	private static String longTermPublicKeysDir = System.getProperty("java.class.path").toString().split(";")[0]+"\\longTermPublicKeys";
	
	/**
	 * Constructor that creates the GUI of the application.
	 */
	public AnonymousForumApp() {
		Dimension dim = new Dimension(900, 3000);
		//create the identification area that includes the id and specific forum public key generation
		JPanel identificationArea = new JPanel();
		identificationArea.setLayout(new FlowLayout()); 
		//id label
		Label idL = new Label("ID:"); 
		identificationArea.add(idL);
		//id text
		final JTextArea idArea = new JTextArea(1, 10);
		JScrollPane idSP = new JScrollPane(idArea); 
		idArea.setEditable(true);
		identificationArea.add(idSP);
		//key generation button
		JButton generateKeyB = new JButton("Generate specific forum keys");
		identificationArea.add(generateKeyB);
		//key text
		final Label keyL = new Label("                                                        \n                                                                                                                                 "); 
		identificationArea.add(keyL);
		
		
		
		//create the key validation area that includes long term public key, specific forum public key and a validity check button
		JPanel keyValidationArea = new JPanel();
		keyValidationArea.setLayout(new BorderLayout());
		keyValidationArea.setBorder(BorderFactory.createLineBorder(Color.black));

		//validate label
		Label validateL = new Label("Validate specific forum public key. User id:"); 
		//user id text
		final JTextArea userID = new JTextArea(1, 10);
		JScrollPane userIdSP = new JScrollPane(userID); 
		userID.setEditable(true);
		JPanel userIDArea = new JPanel();
		userIDArea.setLayout(new FlowLayout());
		userIDArea.add(validateL);
		userIDArea.add(userIdSP);
		keyValidationArea.add(userIDArea, BorderLayout.NORTH);
		//specific key label
		Label specificL = new Label("Specific forum public key path:"); 
		//specific key text
		final JTextArea keyArea = new JTextArea(2, 50);
		JScrollPane keySP = new JScrollPane(keyArea); 
		keyArea.setEditable(true);
		JPanel userKeyArea = new JPanel();
		userKeyArea.setLayout(new FlowLayout());
		userKeyArea.add(specificL);
		userKeyArea.add(keySP);
		//valitade button
		JButton validateB = new JButton("validate key");
		userKeyArea.add(validateB);
		keyValidationArea.add(userKeyArea, BorderLayout.CENTER);
		Label validityResult = new Label("");
		validityResult.setAlignment(1);
		keyValidationArea.add(validityResult, BorderLayout.SOUTH);
		JPanel getKeysP = new JPanel();
		getKeysP.setLayout(new FlowLayout());
		JButton getPublicKeysB = new JButton("save all specific forum public keys from directory");
		getKeysP.add(getPublicKeysB);
		//create a panel contains the identification and key generation
		JPanel keyGenerationArea = new JPanel();
		keyGenerationArea.setMinimumSize(dim);
		keyGenerationArea.setLayout(new BorderLayout()); 
		keyGenerationArea.add(identificationArea, BorderLayout.NORTH);
		keyGenerationArea.add(keyValidationArea, BorderLayout.CENTER);
		keyGenerationArea.add(getKeysP, BorderLayout.SOUTH);
		
		
		//create a label panel
		JPanel labelArea = new JPanel();
		labelArea.setLayout(new FlowLayout()); 
		//label
		Label messageL = new Label("Write your message here:"); 
		labelArea.add(messageL);
		
		//create a post area contains the message and a post button
		JPanel postArea = new JPanel();
		postArea.setLayout(new FlowLayout()); 
		//message text
		final JTextArea messageArea = new JTextArea(10, 30);
		JScrollPane messageSP = new JScrollPane(messageArea); 
		messageArea.setEditable(true);
		postArea.add(messageSP);
		//post button
		JButton sendB = new JButton("post");
		postArea.add(sendB);
		//create a massage post area contains the label area and the post area
		JPanel messagePostArea = new JPanel();
		messagePostArea.setLayout(new BorderLayout());
		messagePostArea.add(labelArea, BorderLayout.NORTH);
		messagePostArea.add(postArea, BorderLayout.CENTER);
		
		Label attachL = new Label("attachment path:"); 
		//verify file name
		final JTextArea signatureArea = new JTextArea(1, 30);
		JScrollPane signatureSP = new JScrollPane(signatureArea); 
		signatureArea.setEditable(true);
		//verify button	area
		JPanel buttonArea = new JPanel();
		buttonArea.setLayout(new FlowLayout()); 
		//verify button
		JButton verifyB = new JButton("verify");
		buttonArea.add(verifyB);
		
		//create the verify area contains the file name and the verify button
		JPanel verifyArea = new JPanel();
		verifyArea.setLayout(new FlowLayout());
		verifyArea.add(attachL);
		verifyArea.add(signatureSP);
		verifyArea.add(buttonArea);
		
		
		
		//create the result area
		JPanel resultArea = new JPanel();
		resultArea.setLayout(new FlowLayout()); 
		//result label
		final JLabel resultL = new JLabel(" "); 
		resultArea.add(resultL);
		
		//create an area contains the post and verify areas
		JPanel manageMassagesArea = new JPanel();
		manageMassagesArea.setMinimumSize(dim);
		manageMassagesArea.setLayout(new BorderLayout()); 
		manageMassagesArea.add(messagePostArea, BorderLayout.NORTH);
		manageMassagesArea.add(verifyArea, BorderLayout.CENTER);
		manageMassagesArea.add(resultArea, BorderLayout.SOUTH);
		
		addListeners(idArea, generateKeyB, keyL, validateB, userID, keyArea, validityResult, getPublicKeysB, messageArea,
				sendB, signatureArea, verifyB, resultL);
		
		JTabbedPane tabbedPane = new JTabbedPane();
		tabbedPane.setMaximumSize(dim);
		tabbedPane.addTab("KeyGeneration", keyGenerationArea);
		tabbedPane.setMnemonicAt(0, KeyEvent.VK_1);
		tabbedPane.addTab("Post and verify", manageMassagesArea);
		tabbedPane.setMnemonicAt(1, KeyEvent.VK_2);
		this.add(tabbedPane);
		
		
	}


	/**
	 * Adds the listeners to the buttons in the GUI.
	 * @param idArea
	 * @param generateKeyB
	 * @param keyL
	 * @param validateB
	 * @param userID
	 * @param keyArea
	 * @param validityResult
	 * @param getPublicKeysB
	 * @param messageArea
	 * @param sendB
	 * @param signatureArea
	 * @param verifyB
	 * @param resultL
	 */
	private void addListeners(final JTextArea idArea, JButton generateKeyB,
			final Label keyL, JButton validateB, final JTextArea userID, final JTextArea keyArea, final Label validityResult, JButton getPublicKeysB,
			final JTextArea messageArea, JButton sendB,
			final JTextArea signatureArea, JButton verifyB, final JLabel resultL) {
		
		//add the listener to the generate specific forum keys button
		generateKeyB.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e){
				//if there is no id tell the user to give it
				if (idArea.getText().equals("")){
					keyL.setText("id is illegal");
					return;
				}
				int id = Integer.parseInt(idArea.getText());
				//if the id is legal
				if (id >= 0 && id < n){
					createForum(id); // create the forum
					try {
						//generate the forum keys
						forum.generateSpecificForumKeys();
					} catch (UnInitializedException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					}
					AnonymousForumSpecificPublicKey key = forum.getForumSpecificPublicKey();
					// Serialize data object to a file
					File file = new File(specificFuromPublicKeysDir+ "\\" + id + ".doc");
					ObjectOutput out;
					try {
						out = new ObjectOutputStream(new FileOutputStream(file));
						out.writeObject(key);
						out.close();
						keyL.setText("specific forum public key file is at " + file.getAbsolutePath());
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
						// TODO Auto-generated catch block 
						e1.printStackTrace();
					}
				} else{
					keyL.setText("id must be between 0 to n");
				}
				
			}
		});
		
		//add the listener to the validate specific forum keys button
		validateB.addActionListener(new ActionListener() {
			
			public void actionPerformed(ActionEvent arg0) {
				//if the user id is ilegat tell the user
				if (userID.getText().equals("")){
					validityResult.setText("user id is illegal");
					return;
				}
				int id = Integer.parseInt(userID.getText());
				//check if the user id is legal
				if (id >= 0 && id < n){
					//if the forum is not created yet, create it.
					if (forum == null){
						createForum(id);
					}
					//get the user specific key
					ObjectInputStream in;
					try {
						in = new ObjectInputStream(new FileInputStream(keyArea.getText()));
						AnonymousForumSpecificPublicKey key = (AnonymousForumSpecificPublicKey) in.readObject();
						//check the validity
						boolean validity = forum.validate(allLongTermPublicKeys[id], key);
						//write the result to the sfreen
						if (validity){
							validityResult.setText("specific user key is valid");
						} else{
							validityResult.setText("specific user key is not valid");
						}
					} catch (FileNotFoundException e) {
						e.printStackTrace();
					} catch (IOException e){ 
						e.printStackTrace();
					} catch (UnInitializedException e) {
						e.printStackTrace();
					} catch (ClassNotFoundException e) {
						e.printStackTrace();
					}
					
				} else{
					validityResult.setText("user id must be between 0 to n");
					return;
				}
			}
		});
		
		//add the listener to the get all specific forum public keys button
		getPublicKeysB.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e){
				//if the id is missing tell the user
				if (idArea.getText().equals("")){
					keyL.setText("id is illegal");
					return;
				}
				int id = Integer.parseInt(idArea.getText());
				//if the forum is not created yet - create it 
				if (forum == null) {
					if (id >= 0 && id < n){
						createForum(id);
					} else {
						keyL.setText("id must be between 0 to n");
						return;
					}
				}
				//if the forum didn't generate specific forum public key - tell the user
				if (forum.getForumSpecificPublicKey() == null){
					keyL.setText("you must generate specific forum keys");
				}
				
				//get all the forum public keys and set them
				File file = new File(specificFuromPublicKeysDir);
				File[] list = file.listFiles();
				allSpecificForumPublicKeys = new AnonymousForumSpecificPublicKey[n];
				
				for (int i=0; i<list.length; i++){
					ObjectInputStream in;
					try {
						in = new ObjectInputStream(new FileInputStream(list[i]));
						AnonymousForumSpecificPublicKey key = (AnonymousForumSpecificPublicKey) in.readObject();
						int userId = Integer.parseInt(list[i].getName().split(".doc")[0]);
						allSpecificForumPublicKeys[userId] = key;
						System.out.println("get specific public key of user with ID - " + userId);
					} catch (FileNotFoundException e1) {
						e1.printStackTrace();
					} catch (IOException e1) {
						e1.printStackTrace();
					} catch (ClassNotFoundException e1) {
						e1.printStackTrace();
					}
					
				}
				
				forum.setAllParticipantsPublicKeys(allSpecificForumPublicKeys);
			}
			
		});
		
		//add the listener to the post message button
		sendB.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e){
				try {
					//post the message, to get the attachment
					PostedMessage postedMessage = forum.post(messageArea.getText().getBytes());
					// Serialize the attachment to a file
					File file = new File("attachment.doc");
					 ObjectOutput out = new ObjectOutputStream(new FileOutputStream(file));
					 out.writeObject(postedMessage);
					 out.close();
					
					 //write the file path to the screen
					 signatureArea.setText(file.getAbsolutePath());
					 
				} catch (UnInitializedException e1) {
					e1.printStackTrace();
				} catch (IOException e1) {
					e1.printStackTrace();
				} 
				resultL.setText("message posted!");
			}
		});
		
		//add the listener to the verify button
		verifyB.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e){
				//get the attachment path
				String fileName = signatureArea.getText();
				
				boolean isVerify = false;
				try {
					//build the attachment file
					ObjectInputStream in = new ObjectInputStream(new FileInputStream(new File(fileName)));
					PostedMessage message = (PostedMessage) in.readObject();
					//verify the atachment
					isVerify = forum.verifyPost(message, messageArea.getText().getBytes());
					in.close();
				} catch (IOException e1) {
				} catch (UnInitializedException e1) {
					e1.printStackTrace();
				} catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				} 
				//write the verify result to the screen
				if (isVerify == true){
					resultL.setText("Message has been verified!");
				} else{
					resultL.setText("Message has not been verified!");
				}
			}
		});
	}
		

	/**
	 * Creates and show the GUI/ This function is called in the beginning of the application
	 */
	private static void createAndShowGUI() {
		 //Create and set up the window. 
		 JFrame frame = new JFrame("AnonymousForum");
		 frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		//Create and set up the content pane.
		 AnonymousForumApp newContentPane = new AnonymousForumApp();
		 newContentPane.setOpaque(true); 
	     frame.setContentPane(newContentPane);

		 //Display the window. 
		 frame.pack();
		 frame.setVisible(true);
	}
	 
	
	/**
	 * Creates the forum. 
	 * @param id - user id
	 */
	private static void createForum(int id) {
		//Dlog and parameters are fixed for now - Koblitz curve over F2m, with m = 233. provider = Miracl. 
		DlogGroup dlog = null;
		try {
			dlog = new MiraclDlogECF2m("K-233");
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//Crtptographic hash are fixed for now - SHA224, provider = BC
		CryptographicHash hashH = new BcSHA224();
		CryptographicHash hashG = new BcSHA224();
		try {
			//creates the forum
			forum = new ForumUser(dlog, hashH, hashG, 5, id, n, new SecureRandom());
			
			// Generate user's long term public key and specific forum public
			// key
			/*forum.generateLongTermKeys();
			AnonymousForumLongTermPublicKey key = forum.getLongtermPublicKey();
			
			// Serialize data object to a file
			File file = new File(longTermPublicKeysDir+ "\\" + id + ".doc");
			ObjectOutput out;
			try {
				out = new ObjectOutputStream(new FileOutputStream(file));
				out.writeObject(key);
				out.close();
			} catch (FileNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			*/
			// Keep track of the user
			getAllLongTermPublicKeys();
			
			//get the long term private key of the user 
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(System.getProperty("java.class.path").toString().split(";")[0]+"\\longTermPrivateKeys\\" + id + ".doc"));
			AnonymousForumLongTermPrivateKey privKey = (AnonymousForumLongTermPrivateKey) in.readObject();
			//set the long term keys of the user
			forum.setLongTermKeys(allLongTermPublicKeys[id], privKey);
			
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} catch (UnInitializedException e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Read all the long term public keys from the files.
	 */
	private static void getAllLongTermPublicKeys(){
		
		allLongTermPublicKeys = new AnonymousForumLongTermPublicKey[n]; //contains all the public keys
		
		File file = new File(longTermPublicKeysDir);
		File[] list = file.listFiles();
		//for all file in the directory, build
		for (int i=0; i<list.length; i++){
			ObjectInputStream in;
			try {
				in = new ObjectInputStream(new FileInputStream(list[i]));
				AnonymousForumLongTermPublicKey key = (AnonymousForumLongTermPublicKey) in.readObject();
				int id = Integer.parseInt(list[i].getName().split(".doc")[0]);
				allLongTermPublicKeys[id] = key;
				System.out.println("get long term public key of user with ID - " + id);
			} catch (FileNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
		}
		
		
	}

	public static void main(String[] args) {
		 //Schedule a job for the event-dispatching thread:
		 //creating and showing this application's GUI. 
		 javax.swing.SwingUtilities.invokeLater(new Runnable() {
			 public void run() { 
				 new File(specificFuromPublicKeysDir).mkdir();
				 new File(System.getProperty("java.class.path").toString().split(";")[0]+"\\longTermPrivateKeys").mkdir();
				 //createForum();
				 createAndShowGUI();
			}
		});
	} 
}
