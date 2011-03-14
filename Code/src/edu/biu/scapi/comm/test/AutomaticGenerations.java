/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.test.
 * File: AutomaticGenerations.java.
 * Creation date Mar 10, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm.test;

/**
 * @author LabTest
 *
 */
public class AutomaticGenerations {

	/**
	 * main
	 * @param args
	 */
	public static void main(String[] args) {
		
		AutomaticPropertiesFilesBuilder propertiesBuilder = new AutomaticPropertiesFilesBuilder(100, 8000, "132.70.6.63", "Party");
		
		propertiesBuilder.generateAllPropertiesFiles();
		propertiesBuilder.generateAllBatchFiles();
	}

}
