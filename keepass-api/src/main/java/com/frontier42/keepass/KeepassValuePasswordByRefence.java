package com.frontier42.keepass;

public class KeepassValuePasswordByRefence extends KeepassValueByRefence {

	public KeepassValuePasswordByRefence(KeepassEntry entry, String targetUUID) {
		super(entry, targetUUID);
	}

	@Override
	String getRefValue(KeepassEntry targetEntry) {
		return targetEntry.getPassword().getValue();
	}

}
