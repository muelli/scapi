/**
 * 
 */
package edu.biu.scapi.tests;

import java.io.PrintWriter;

/** 
 * @author LabTest
 */
public abstract class Test {
	protected abstract void wrongBehavior(PrintWriter file);
	
	protected abstract void testVector(PrintWriter file);

}