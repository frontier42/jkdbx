package com.frontier42.keepass.impl;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StreamCipherDelegator implements StreamCipher {
	private final Logger LOG=LoggerFactory.getLogger(getClass()); 
	private StreamCipher delegator;
	public StreamCipherDelegator(StreamCipher delegator) {
		this.delegator=delegator;
	}
	public void init(boolean forEncryption, CipherParameters params)
			throws IllegalArgumentException {
		delegator.init(forEncryption, params);
	}

	public String getAlgorithmName() {
		return delegator.getAlgorithmName();
	}

	public byte returnByte(byte in) {
		return delegator.returnByte(in);
	}

	public void processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
		if (LOG.isDebugEnabled()){
			LOG.debug("decrypting:'{}'", javax.xml.bind.DatatypeConverter.printBase64Binary(in));
		}
		delegator.processBytes(in, inOff, len, out, outOff);
		if (LOG.isDebugEnabled()){
			LOG.debug("decrypted:'{}' --> '{}'", len, javax.xml.bind.DatatypeConverter.printBase64Binary(in), new String(out));
		}
	}

	public void reset() {
		delegator.reset();
	}
}
