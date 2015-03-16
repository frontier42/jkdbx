package com.frontier42.keepass;

import java.util.regex.Matcher;



public class KeepassEntry {
	private final KeepassGroup group;
	
	private String title;
	private KeepassValue username;
	private KeepassValue password;
	private String uuid;
	
	public KeepassEntry(KeepassGroup group) {
		this.group=group;
	}
	public String getTitle() {
		return title;
	}
	public void setTitle(String title) {
		this.title = title;
	}
	public KeepassValue getUsername() {
		return username;
	}
	public void setUsername(KeepassValue username) {
		this.username = username;
	}
	public KeepassValue getPassword() {
		return password;
	}
	public void setPassword(KeepassValue password) {
		this.password = password;
	}
	public String getUUID() {
		return uuid;
	}
	public void setUUID(String uuid) {
		this.uuid=uuid;
	}
	@Override
	public int hashCode() {
		return this.uuid.hashCode();
	}
	public KeepassGroup getGroup() {
		return group;
	}
	public KeepassValue createEncryptedValue(String value){
		return new KeepassValueEncrypted(value);
	}
	public KeepassValue createValue(String value){
		return this.getGroup().getDatabase().createValue(this, value);
	}
}
