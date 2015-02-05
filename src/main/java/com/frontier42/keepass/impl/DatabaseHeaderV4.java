package com.frontier42.keepass.impl;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.frontier42.keepass.KeepassDatabaseFactory;
import com.keepassdroid.database.CrsAlgorithm;
import com.keepassdroid.database.PwCompressionAlgorithm;
import com.keepassdroid.database.exception.InvalidDBVersionException;
import com.keepassdroid.stream.LEDataInputStream;
import com.keepassdroid.utils.Types;

public class DatabaseHeaderV4 {
	public static final int PWM_DBSIG_1 = 0x9AA2D903;
	public static final int DBSIG_2               = 0xB54BFB67;
	private static final int FILE_VERSION_CRITICAL_MASK = 0xFFFF0000;
	public static final int FILE_VERSION_32 =             0x00030001;
	
	/** Seed that gets hashed with the userkey to form the final key */
	public byte masterSeed[];

	/** Used for the dwKeyEncRounds AES transformations */
	public byte transformSeed[] = new byte[32];
	
	/** IV used for content encryption */
	public byte encryptionIV[] = new byte[16];
	
	public byte[] protectedStreamKey = new byte[32];
	public byte[] streamStartBytes = new byte[32];
	public CrsAlgorithm innerRandomStream;
	
	private final DatabaseReaderV4 db;
	
	public class PwDbHeaderV4Fields {
		public static final byte EndOfHeader = 0;
		public static final byte Comment = 1;
		public static final byte CipherID = 2;
		public static final byte CompressionFlags = 3;
		public static final byte MasterSeed = 4;
		public static final byte TransformSeed = 5;
		public static final byte TransformRounds = 6;
		public static final byte EncryptionIV = 7;
		public static final byte ProtectedStreamKey = 8;
		public static final byte StreamStartBytes = 9;
		public static final byte InnerRandomStreamID = 10;
	}
	public DatabaseHeaderV4(DatabaseReaderV4 databaseReaderV4) {
		this.db=databaseReaderV4;
	}
	
	@SuppressWarnings("resource")
	public byte[] load(InputStream istream) throws IOException, InvalidDBVersionException{
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("No SHA-256 implementation");
		}
		DigestInputStream dis = new DigestInputStream(istream, md);
		LEDataInputStream lis = new LEDataInputStream(dis);
		int sig1 = lis.readInt();
		int sig2 = lis.readInt();
		
		if ( ! matchesHeader(sig1, sig2) ) {
			throw new InvalidDBVersionException();
		}
		
		long version = lis.readUInt();
		if ( ! validVersion(version) ) {
			throw new InvalidDBVersionException();
		}
		
		boolean done = false;
		while ( ! done ) {
			done = readHeaderField(lis);
		}
		
		return md.digest();
	}
	
	/** Determines if this is a supported version.
	 * 
	 *  A long is needed here to represent the unsigned int since we perform
	 *  arithmetic on it.
	 * @param version
	 * @return
	 */
	private boolean validVersion(long version) {
		
		return ! ((version & FILE_VERSION_CRITICAL_MASK) > (FILE_VERSION_32 & FILE_VERSION_CRITICAL_MASK));
		
	}

	public static boolean matchesHeader(int sig1, int sig2) {
		return (sig1 == PWM_DBSIG_1) && ( (sig2 == DBSIG_2) || (sig2 == DBSIG_2) );
	}
	private boolean readHeaderField(LEDataInputStream dis) throws IOException {
		byte fieldID = (byte) dis.read();
		
		int fieldSize = dis.readUShort();
		
		byte[] fieldData = null;
		if ( fieldSize > 0 ) {
			fieldData = new byte[fieldSize];
			
			int readSize = dis.read(fieldData);
			if ( readSize != fieldSize ) {
				throw new IOException("Header ended early.");
			}
		}
		
		switch ( fieldID ) {
			case PwDbHeaderV4Fields.EndOfHeader:
				return true;
				
			case PwDbHeaderV4Fields.CipherID:
				setCipher(fieldData);
				break;
				
			case PwDbHeaderV4Fields.CompressionFlags:
				setCompressionFlags(fieldData);
				break;
				
			case PwDbHeaderV4Fields.MasterSeed:
				masterSeed = fieldData;
				break;
				
			case PwDbHeaderV4Fields.TransformSeed:
				transformSeed = fieldData;
				break;
				
			case PwDbHeaderV4Fields.TransformRounds:
				setTransformRounds(fieldData);
				break;
				
			case PwDbHeaderV4Fields.EncryptionIV:
				encryptionIV = fieldData;
				break;
				
			case PwDbHeaderV4Fields.ProtectedStreamKey:
				protectedStreamKey = fieldData;
				break;
				
			case PwDbHeaderV4Fields.StreamStartBytes:
				streamStartBytes = fieldData;
				break;
			
			case PwDbHeaderV4Fields.InnerRandomStreamID:
				setRandomStreamID(fieldData);
				break;
				
			default:
				throw new IOException("Invalid header type.");
			
		}
		
		return false;
	}
	private void setCipher(byte[] pbId) throws IOException {
		if ( pbId == null || pbId.length != 16 ) {
			throw new IOException("Invalid cipher ID.");
		}
		
		db.dataCipher = Types.bytestoUUID(pbId);
	}
	private void setCompressionFlags(byte[] pbFlags) throws IOException {
		if ( pbFlags == null || pbFlags.length != 4 ) {
			throw new IOException("Invalid compression flags.");
		}
		
		int flag = LEDataInputStream.readInt(pbFlags, 0);
		if ( flag < 0 || flag >= PwCompressionAlgorithm.count ) {
			throw new IOException("Unrecognized compression flag.");
		}
		
		db.compressionAlgorithm = PwCompressionAlgorithm.fromId(flag);
		
	}
	private void setTransformRounds(byte[] rounds) throws IOException {
		if ( rounds == null || rounds.length != 8 ) {
			throw new IOException("Invalid rounds.");
		}
		
		long rnd = LEDataInputStream.readLong(rounds, 0);
		
		if ( rnd < 0 || rnd > Integer.MAX_VALUE ) {
			//TODO: Actually support really large numbers
			throw new IOException("Rounds higher than " + Integer.MAX_VALUE + " are not currently supported.");
		}
		
		db.numKeyEncRounds = rnd;
	}
	private void setRandomStreamID(byte[] streamID) throws IOException {
		if ( streamID == null || streamID.length != 4 ) {
			throw new IOException("Invalid stream id.");
		}
		
		int id = LEDataInputStream.readInt(streamID, 0);
		if ( id < 0 || id >= CrsAlgorithm.count ) {
			throw new IOException("Invalid stream id.");
		}
		
		innerRandomStream = CrsAlgorithm.fromId(id);
	}
}
