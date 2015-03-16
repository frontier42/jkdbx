package com.frontier42.keepass;

import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;
import java.util.regex.Matcher;

public class KeepassDatabase {
	private Map<MyKeyReferencey, KeepassGroup> groups=KeepassGroup.MAKE_MAP();
	private Map<String, KeepassEntry> cache=new Hashtable<String, KeepassEntry>();
	private KeepassGroup rootGroup;
	
	public void add(KeepassGroup group) {
		groups.put(KeepassGroup.MAKE_KEY(group),group);
	}
	public Collection<KeepassGroup> getGroups() {
		return groups.values();
	}
	public KeepassGroup newGroup() {
		return new KeepassGroup(this);
	}
	public KeepassEntry getEntryByUUID(String targetUUID) {
		return cache.get(targetUUID);
	}
	protected void onAdd(KeepassEntry entry){
		cache.put(entry.getUUID(), entry);
	}
	public KeepassValue createValue(KeepassEntry ownerEntry, String value){
		if (value.startsWith("{REF:")){
			return createValueByRef(ownerEntry, value);
		}else{
			return createValueByVal(ownerEntry, value);
		}
	}
	public KeepassValue createValueByVal(KeepassEntry ownerEntry, String value){
		return new KeepassValueByValue(value);
	}
	public KeepassValue createValueByRef(KeepassEntry ownerEntry, String value){
		Matcher m=KeepassValueByRefence.REF_REGEX.matcher(value);
		if (m.matches()){
			if ("U".equals(m.group(1))){
				return new KeepassValueUsernameByRefence(ownerEntry, m.group(3));
			}else if ("P".equals(m.group(1))){
				return new KeepassValuePasswordByRefence(ownerEntry, m.group(3));
			}
		}
		return  createValueByVal(ownerEntry, value);
	}
	public void onAdd(KeepassGroup group) {
	}
	public void setRootGroup(KeepassGroup group) {
		this.rootGroup=group;
	}
	public KeepassGroup getRootGroup() {
		return rootGroup;
	}
}
