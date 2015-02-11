package com.frontier42.keepass;

public class KeepassValueUsernameByRefence extends KeepassValueByRefence {

	public KeepassValueUsernameByRefence(KeepassEntry entry, String targetUUID) {
		super(entry, targetUUID);
	}

	@Override
	String getRefValue(KeepassEntry targetEntry) {
		return targetEntry.getUsername().getValue();
	}

}
