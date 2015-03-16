package com.frontier42.keepass;


public class MyKey<V> implements MyKeyReferencey {
	private V _value;
	private EqualsComparator _comparator;
	
	public MyKey(V value, EqualsComparator comparator){
		this._value=value;
		this._comparator=comparator;
	}
	@Override
	public int hashCode() {
		return this._comparator.hashCode(_value);
	}
	@Override
	public boolean equals(Object obj) {
		return _comparator.equals(_value, obj);
	}
}