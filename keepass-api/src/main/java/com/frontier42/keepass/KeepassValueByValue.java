package com.frontier42.keepass;

public class KeepassValueByValue implements KeepassValue {
	private String value;
	public KeepassValueByValue(String value){
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
