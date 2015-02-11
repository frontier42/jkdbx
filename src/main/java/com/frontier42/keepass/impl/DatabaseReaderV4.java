package com.frontier42.keepass.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.DigestOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.StreamCipher;

import com.keepassdroid.crypto.CipherFactory;
import com.keepassdroid.crypto.PwStreamCipherFactory;
import com.keepassdroid.crypto.finalkey.FinalKey;
import com.keepassdroid.crypto.finalkey.FinalKeyFactory;
import com.keepassdroid.database.PwCompressionAlgorithm;
import com.keepassdroid.database.exception.InvalidDBVersionException;
import com.keepassdroid.database.exception.InvalidPasswordException;
import com.keepassdroid.stream.BetterCipherInputStream;
import com.keepassdroid.stream.LEDataInputStream;
import com.keepassdroid.stream.NullOutputStream;

public class DatabaseReaderV4 {
	protected UUID dataCipher;
	protected PwCompressionAlgorithm compressionAlgorithm;
	protected long numKeyEncRounds;
	protected StreamCipher randomStream;

	public byte[] makeFinalKey(byte masterKey[], byte[] masterSeed,
			byte[] masterSeed2, int numRounds) throws IOException {

		// Write checksum Checksum
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("SHA-256 not implemented here.");
		}
		NullOutputStream nos = new NullOutputStream();
		DigestOutputStream dos = new DigestOutputStream(nos, md);

		byte[] transformedMasterKey = transformMasterKey(masterSeed2,
				masterKey, numRounds);
		dos.write(masterSeed);
		dos.write(transformedMasterKey);

		return md.digest();
	}

	/**
	 * Encrypt the master key a few times to make brute-force key-search harder
	 * 
	 * @throws IOException
	 */
	private static byte[] transformMasterKey(byte[] pKeySeed, byte[] pKey,
			int rounds) throws IOException {
		FinalKey key = FinalKeyFactory.createFinalKey();

		return key.transformMasterKey(pKeySeed, pKey, rounds);
	}

	protected byte[] getPasswordKey(String key, String encoding)
			throws IOException {
		assert (key != null);

		if (key.length() == 0)
			throw new IllegalArgumentException("Key cannot be empty.");

		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("SHA-256 not supported");
		}

		byte[] bKey;
		try {
			bKey = key.getBytes(encoding);
		} catch (UnsupportedEncodingException e) {
			assert false;
			bKey = key.getBytes();
		}
		md.update(bKey, 0, bKey.length);

		return md.digest();
	}

	public byte[] getPasswordKey(String key) throws IOException {
		return getPasswordKey(key, "UTF-8");
	}

	public byte[] getMasterKey(String key) throws IOException {
		byte[] fKey;

		fKey = getPasswordKey(key);

		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("No SHA-256 implementation");
		}

		return md.digest(fKey);
	}

	public InputStream openDecryptedStrem(InputStream is, String password) throws IOException, InvalidDBVersionException, InvalidPasswordException{
		// BufferedInputStream bis = new BufferedInputStream(is);
		/*
		 * if ( ! bis.markSupported() ) { throw new
		 * IOException("Input stream does not support mark."); }
		 */

		// We'll end up reading 8 bytes to identify the header. Might as well
		// use two extra.
		// bis.mark(10);

		DatabaseHeaderV4 header = new DatabaseHeaderV4(this);
		header.load(is);
		byte[] finalKey = makeFinalKey(getMasterKey(password),
				header.masterSeed, header.transformSeed,
				(int) this.numKeyEncRounds);
		// bis.reset();
		// bis.skip(8);

		// Attach decryptor
		Cipher cipher;
		try {
			cipher = CipherFactory.getInstance(this.dataCipher,
					Cipher.DECRYPT_MODE, finalKey, header.encryptionIV);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("Invalid algorithm.");
		} catch (NoSuchPaddingException e) {
			throw new IOException("Invalid algorithm.");
		} catch (InvalidKeyException e) {
			throw new IOException("Invalid algorithm.");
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException("Invalid algorithm.");
		}
		InputStream decrypted = new BetterCipherInputStream(is, cipher, 50 * 1024);
		LEDataInputStream dataDecrypted = new LEDataInputStream(decrypted);
		byte[] storedStartBytes = null;
		try {
			storedStartBytes = dataDecrypted.readBytes(32);
			if (storedStartBytes == null || storedStartBytes.length != 32) {
				throw new InvalidPasswordException();
			}
		} catch (IOException e) {
			throw new InvalidPasswordException();
		}

		if (!Arrays.equals(storedStartBytes, header.streamStartBytes)) {
			throw new InvalidPasswordException();
		}
		ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
		OutputStream data=byteArrayOutputStream;
		boolean bexit=false;
		while (!bexit){
			int blockId=dataDecrypted.readInt();
			byte[] blockHash=dataDecrypted.readBytes(32);
			int blockSize=dataDecrypted.readInt();
			if (blockSize>0){
				data.write(dataDecrypted.readBytes(blockSize));
			}else{
				bexit=true;
			}
		}
		//System.err.println(byteArrayOutputStream.toString());
		InputStream hashed = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());

		InputStream decompressed;
		if (this.compressionAlgorithm == PwCompressionAlgorithm.Gzip) {
			decompressed = new GZIPInputStream(hashed);
		} else {
			decompressed = hashed;
		}

		if (header.protectedStreamKey == null) {
			assert (false);
			throw new IOException("Invalid stream key.");
		}
		randomStream = PwStreamCipherFactory.getInstance(
				header.innerRandomStream, header.protectedStreamKey);
		return decompressed;
	}

}
