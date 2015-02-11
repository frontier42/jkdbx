package com.frontier42.keepass;

import java.util.regex.Pattern;

public abstract class KeepassValueByRefence implements KeepassValue {
	public static final Pattern REF_REGEX=Pattern.compile("\\{REF:([^@]+)@([^:]+):([^\\}]+)\\}");
	private final KeepassEntry entry;
	private final String targetUUID;
	private String cache;
	
	public KeepassValueByRefence(KeepassEntry entry, String targetUUID){
		this.entry=entry;
		this.targetUUID=targetUUID;
	}
	public String getValue(){
		if (cache!=null){
			return cache;
		}
		KeepassEntry targetEntry=this.entry.getGroup().getDatabase().getEntryByUUID(this.targetUUID);
		if (targetEntry==null) throw new RuntimeException("UUID Not Found:"+this.targetUUID);
		
		cache=getRefValue(targetEntry);
		return cache;
		
	}
	abstract String getRefValue(KeepassEntry targetEntry);
	@Override
	public String toString() {
		return getValue();
	}
}
