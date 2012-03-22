package edu.biu.scapi.anonymousForums;

class AnonymousForumConfig{
	String dlogGroup = null;
	String dlogProvider = null;
	String algorithmParameterSpec = null;
	String hashH = null;
	String hashHProvider = null;
	String hashG = null;
	String hashGProvider = null;
	String polynomialDegree = null;
	String numOfusers = null;
	public AnonymousForumConfig(String dlogGroup, String dlogProvider,
			String algorithmParameterSpec, String hashH,
			String hashHProvider, String hashG, String hashGProvider,
			String polynomialDegree, String numOfusers) {
		super();
		this.dlogGroup = dlogGroup;
		this.dlogProvider = dlogProvider;
		this.algorithmParameterSpec = algorithmParameterSpec;
		this.hashH = hashH;
		this.hashHProvider = hashHProvider;
		this.hashG = hashG;
		this.hashGProvider = hashGProvider;
		this.polynomialDegree = polynomialDegree;
		this.numOfusers = numOfusers;
	}
	public String getDlogGroup() {
		return dlogGroup;
	}
	public String getDlogProvider() {
		return dlogProvider;
	}
	public String getAlgorithmParameterSpec() {
		return algorithmParameterSpec;
	}
	public String getHashH() {
		return hashH;
	}
	public String getHashHProvider() {
		return hashHProvider;
	}
	public String getHashG() {
		return hashG;
	}
	public String getHashGProvider() {
		return hashGProvider;
	}
	public String getPolynomialDegree() {
		return polynomialDegree;
	}
	public String getNumOfusers() {
		return numOfusers;
	}
	
	
}