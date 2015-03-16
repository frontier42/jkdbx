package com.frontier42.keepass;

public class KeepassValueEncrypted implements KeepassValue {
	private String value;
	public KeepassValueEncrypted(String value){
		this.value=value;
	}
	@Override
	public String getValue() {
		return this.value;
	}
	@Override
	public String toString() {
		return getValue();
	}
}
