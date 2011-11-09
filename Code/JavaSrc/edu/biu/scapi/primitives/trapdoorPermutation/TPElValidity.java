package edu.biu.scapi.primitives.trapdoorPermutation;

/**
 * 
 * @author LabTest
 * enum that represent the possible validity values of trapdoor element.
 * There are three possible validity values: 
 * VALID (it is an element); 
 * NOT_VALID (it is not an element); 
 * DON’T_KNOW (there is not enough information to check if it is an element or not);
 * 
 */
public enum TPElValidity {
	VALID,
	NOT_VALID, 
	DONT_KNOW
}
