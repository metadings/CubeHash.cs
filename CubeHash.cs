/*	CubeHash.cs source code package - C# implementation

	2016-08-19
	Uli Riehm <metadings@live.de>
	Public Domain

	based on supercop-20141124/crypto_hash/cubehash512/unrolled2

	20100726
	D. J. Bernstein
	Public domain.
*/
using System;
using System.Security.Cryptography;

namespace Crypto
{
	public class CubeHash81 : CubeHash { public CubeHash81() : base(256, 1, 8) { } }

	public class CubeHash82 : CubeHash { public CubeHash82() : base(256, 2, 8) { } }

	public class CubeHash84 : CubeHash { public CubeHash84() : base(256, 4, 8) { } }

	public class CubeHash88 : CubeHash { public CubeHash88() : base(256, 8, 8) { } }

	public class CubeHash816 : CubeHash { public CubeHash816() : base(256, 16, 8) { } }

	// CubeHash256: 16 bytes hash sourcecode input, 8 rounds, 256 bits (32 bytes) hash value output
	public class CubeHash256 : CubeHash { public CubeHash256() : base(256, 16, 8) { } }

	public class CubeHash832 : CubeHash { public CubeHash832() : base(256, 32, 8) { } }


	public class CubeHash161 : CubeHash { public CubeHash161() : base(512, 1, 16) { } }

	public class CubeHash162 : CubeHash { public CubeHash162() : base(512, 2, 16) { } }

	public class CubeHash164 : CubeHash { public CubeHash164() : base(512, 4, 16) { } }

	public class CubeHash168 : CubeHash { public CubeHash168() : base(512, 8, 16) { } }

	public class CubeHash1616 : CubeHash { public CubeHash1616() : base(512, 16, 16) { } }

	public class CubeHash1632 : CubeHash { public CubeHash1632() : base(512, 32, 16) { } }

	// CubeHash512: 32 bytes hash sourcecode input, 16 rounds, 512 bits (64 bytes) hash value output
	public class CubeHash512 : CubeHash { public CubeHash512() : base() { } }


	public class CubeHash : HashAlgorithm // IDisposable
	{
		private readonly int hashSize = 512;

		public override int HashSize { get { return hashSize; } }

		public int HashSizeInBytes { get { return hashSize / 8; } }

		// public int HashSizeInUInt32 { get { return HashSizeInBytes / 4; } }

		public readonly int BlockSizeInBytes = 32;

		// public int BlockSizeInUInt32 { get { return BlockSizeInBytes / 4; } }

		private int pos;

		private readonly uint[] state = new uint[32];

		public readonly int ROUNDS = 16;

		// CubeHash512
		public CubeHash() { }

		public CubeHash(int hashSizeInBits)
		{
			if (hashSizeInBits < 8) // || hashSizeInBits > 512)
				throw new ArgumentOutOfRangeException("hashSizeInBits");
			if (hashSizeInBits % 8 != 0)
				throw new ArgumentOutOfRangeException("hashSizeInBits", "must be a multiple of 8");
			
			this.hashSize = hashSizeInBits;
		}

		public CubeHash(int hashSizeInBits, int blockSizeInBytes)
			: this(hashSizeInBits)
		{
			if (blockSizeInBytes < 1)
				throw new ArgumentOutOfRangeException("blockSizeInBytes");
			
			this.BlockSizeInBytes = blockSizeInBytes;
		}

		public CubeHash(int hashSizeInBits, int blockSizeInBytes, int rounds)
			: this(hashSizeInBits, blockSizeInBytes)
		{
			if (rounds < 8)
				throw new ArgumentOutOfRangeException("rounds");

			this.ROUNDS = rounds;
		}

		private bool isInitialized = false;

		public override void Initialize()
		{
			HashClear();

			isInitialized = true;

			state[0] = (uint)HashSizeInBytes;
			state[1] = (uint)BlockSizeInBytes;
			state[2] = (uint)ROUNDS;
			TransformBlock();
		}

		// public void Dispose() { Dispose(true); }

		protected override void Dispose(bool disposing) { if (disposing) HashClear(); base.Dispose(disposing); }

		public virtual void HashClear()
		{
			isInitialized = false;

			pos = 0;
			for (int i = 0; i < state.Length; ++i) state[i] = 0U;
		}

		protected override void HashCore(byte[] array, int start, int count)
		{
			Core(array, start, count);
		}

		public virtual void Core(byte[] array, int start, int count)
		{
			if (array == null)
				throw new ArgumentNullException("array");
			if (start < 0)
				throw new ArgumentOutOfRangeException("start");
			if (count < 0)
				throw new ArgumentOutOfRangeException("count");
			if (start + count > array.Length)
				throw new ArgumentOutOfRangeException("start + count");
			
			if (!isInitialized) Initialize();

			uint u;
			while (0 < count)
			{
				u = (uint)array[start];
				u <<= 8 * ((pos / 8) % 4);
				state[pos / 32] ^= u;

				start += 1;
				count -= 1;
				pos += 8;

				if (pos == 8 * BlockSizeInBytes)
				{
					TransformBlock();
					pos = 0;
				}
			}
		}

		protected override byte[] HashFinal()
		{
			return Final();
		}

		public virtual byte[] Final()
		{
			var hash = new byte[HashSizeInBytes];
			Final(hash);
			return hash;
		}

		public virtual void Final(byte[] hash)
		{
			if (hash.Length != HashSizeInBytes)
				throw new ArgumentOutOfRangeException("hash", 
					string.Format("hash.Length must be {0} HashSizeInBytes",
						HashSizeInBytes));
			
			if (!isInitialized) Initialize();

			var u = (uint)(128 >> (pos % 8));
			u <<= 8 * ((pos / 8) % 4);
			state[pos / 32] ^= u;
			TransformBlock();

			state[31] ^= 1U;
			TransformBlock();
			TransformBlock();
			
			for (int i = 0; i < HashSizeInBytes; ++i) 
				hash[i] = (byte)(state[i / 4] >> (8 * (i % 4)));

			isInitialized = false;
		}

		public virtual void Compute(byte[] value, byte[] sourceCode)
		{
			Core(sourceCode, 0, sourceCode.Length);
			Final(value);
		}

		public virtual byte[] Compute(byte[] sourceCode)
		{
			var value = new byte[HashSizeInBytes];
			Core(sourceCode, 0, sourceCode.Length);
			Final(value);
			return value;
		}

		public override byte[] Hash
		{
			get {
				// if (m_bDisposed) throw new ObjectDisposedException(null);
				// if (State != 0) throw new CryptographicUnexpectedOperationException(Environment.GetResourceString("Cryptography_HashNotYetFinalized"));

				// Output
				var hash = new byte[HashSizeInBytes];
				for (int i = 0; i < HashSizeInBytes; ++i) 
					hash[i] = (byte)(state[i / 4] >> (8 * (i % 4)));
				return hash;
			}
		}

		// Beware. A ROTATE method would be nice, but this halfes the speed of CubeHash.cs
		// static uint ROTATE(uint a, int b) { return ((a << b) | (a >> (32 - b))); }

		protected void TransformBlock()
		{
			uint x00 = state[0], x01 = state[1], x02 = state[2], x03 = state[3];
			uint x04 = state[4], x05 = state[5], x06 = state[6], x07 = state[7];
			uint x08 = state[8], x09 = state[9], x0A = state[10], x0B = state[11];
			uint x0C = state[12], x0D = state[13], x0E = state[14], x0F = state[15];
			uint x10 = state[16], x11 = state[17], x12 = state[18], x13 = state[19];
			uint x14 = state[20], x15 = state[21], x16 = state[22], x17 = state[23];
			uint x18 = state[24], x19 = state[25], x1A = state[26], x1B = state[27];
			uint x1C = state[28], x1D = state[29], x1E = state[30], x1F = state[31];

			uint y0, y1, y2, y3, y4, y5, y6, y7;
			uint y8, y9, yA, yB, yC, yD, yE, yF;

			for (int r = 0; r < ROUNDS; ++r)
			{
				x10 += x00; x11 += x01; x12 += x02; x13 += x03;
				x14 += x04; x15 += x05; x16 += x06; x17 += x07;
				x18 += x08; x19 += x09; x1A += x0A; x1B += x0B;
				x1C += x0C; x1D += x0D; x1E += x0E; x1F += x0F;

				y8 = x00; y9 = x01; yA = x02; yB = x03;
				yC = x04; yD = x05; yE = x06; yF = x07;
				y0 = x08; y1 = x09; y2 = x0A; y3 = x0B;
				y4 = x0C; y5 = x0D; y6 = x0E; y7 = x0F;

				x00 = ((y0 << 7) | (y0 >> (32 - 7))); // ROTATE(y0, 7);
				x01 = ((y1 << 7) | (y1 >> (32 - 7))); // ROTATE(y1, 7);
				x02 = ((y2 << 7) | (y2 >> (32 - 7))); // ROTATE(y2, 7);
				x03 = ((y3 << 7) | (y3 >> (32 - 7))); // ROTATE(y3, 7);
				x04 = ((y4 << 7) | (y4 >> (32 - 7))); // ROTATE(y4, 7);
				x05 = ((y5 << 7) | (y5 >> (32 - 7))); // ROTATE(y5, 7);
				x06 = ((y6 << 7) | (y6 >> (32 - 7))); // ROTATE(y6, 7);
				x07 = ((y7 << 7) | (y7 >> (32 - 7))); // ROTATE(y7, 7);
				x08 = ((y8 << 7) | (y8 >> (32 - 7))); // ROTATE(y8, 7);
				x09 = ((y9 << 7) | (y9 >> (32 - 7))); // ROTATE(y9, 7);
				x0A = ((yA << 7) | (yA >> (32 - 7))); // ROTATE(yA, 7);
				x0B = ((yB << 7) | (yB >> (32 - 7))); // ROTATE(yB, 7);
				x0C = ((yC << 7) | (yC >> (32 - 7))); // ROTATE(yC, 7);
				x0D = ((yD << 7) | (yD >> (32 - 7))); // ROTATE(yD, 7);
				x0E = ((yE << 7) | (yE >> (32 - 7))); // ROTATE(yE, 7);
				x0F = ((yF << 7) | (yF >> (32 - 7))); // ROTATE(yF, 7);

				x00 ^= x10; x01 ^= x11; x02 ^= x12; x03 ^= x13;
				x04 ^= x14; x05 ^= x15; x06 ^= x16; x07 ^= x17;
				x08 ^= x18; x09 ^= x19; x0A ^= x1A; x0B ^= x1B;
				x0C ^= x1C; x0D ^= x1D; x0E ^= x1E; x0F ^= x1F;

				y2 = x10; y3 = x11; y0 = x12; y1 = x13;
				y6 = x14; y7 = x15; y4 = x16; y5 = x17;
				yA = x18; yB = x19; y8 = x1A; y9 = x1B;
				yE = x1C; yF = x1D; yC = x1E; yD = x1F;

				x10 = y0; x11 = y1; x12 = y2; x13 = y3;
				x14 = y4; x15 = y5; x16 = y6; x17 = y7;
				x18 = y8; x19 = y9; x1A = yA; x1B = yB;
				x1C = yC; x1D = yD; x1E = yE; x1F = yF;

				x10 += x00; x11 += x01; x12 += x02; x13 += x03;
				x14 += x04; x15 += x05; x16 += x06; x17 += x07;
				x18 += x08; x19 += x09; x1A += x0A; x1B += x0B;
				x1C += x0C; x1D += x0D; x1E += x0E; x1F += x0F;

				y4 = x00; y5 = x01; y6 = x02; y7 = x03;
				y0 = x04; y1 = x05; y2 = x06; y3 = x07;
				yC = x08; yD = x09; yE = x0A; yF = x0B;
				y8 = x0C; y9 = x0D; yA = x0E; yB = x0F;

				x00 = ((y0 << 11) | (y0 >> (32 - 11))); // ROTATE(y0, 11);
				x01 = ((y1 << 11) | (y1 >> (32 - 11))); // ROTATE(y1, 11);
				x02 = ((y2 << 11) | (y2 >> (32 - 11))); // ROTATE(y2, 11);
				x03 = ((y3 << 11) | (y3 >> (32 - 11))); // ROTATE(y3, 11);
				x04 = ((y4 << 11) | (y4 >> (32 - 11))); // ROTATE(y4, 11);
				x05 = ((y5 << 11) | (y5 >> (32 - 11))); // ROTATE(y5, 11);
				x06 = ((y6 << 11) | (y6 >> (32 - 11))); // ROTATE(y6, 11);
				x07 = ((y7 << 11) | (y7 >> (32 - 11))); // ROTATE(y7, 11);
				x08 = ((y8 << 11) | (y8 >> (32 - 11))); // ROTATE(y8, 11);
				x09 = ((y9 << 11) | (y9 >> (32 - 11))); // ROTATE(y9, 11);
				x0A = ((yA << 11) | (yA >> (32 - 11))); // ROTATE(yA, 11);
				x0B = ((yB << 11) | (yB >> (32 - 11))); // ROTATE(yB, 11);
				x0C = ((yC << 11) | (yC >> (32 - 11))); // ROTATE(yC, 11);
				x0D = ((yD << 11) | (yD >> (32 - 11))); // ROTATE(yD, 11);
				x0E = ((yE << 11) | (yE >> (32 - 11))); // ROTATE(yE, 11);
				x0F = ((yF << 11) | (yF >> (32 - 11))); // ROTATE(yF, 11);

				x00 ^= x10; x01 ^= x11; x02 ^= x12; x03 ^= x13;
				x04 ^= x14; x05 ^= x15; x06 ^= x16; x07 ^= x17;
				x08 ^= x18; x09 ^= x19; x0A ^= x1A; x0B ^= x1B;
				x0C ^= x1C; x0D ^= x1D; x0E ^= x1E; x0F ^= x1F;

				y1 = x10; y0 = x11; y3 = x12; y2 = x13;
				y5 = x14; y4 = x15; y7 = x16; y6 = x17;
				y9 = x18; y8 = x19; yB = x1A; yA = x1B;
				yD = x1C; yC = x1D; yF = x1E; yE = x1F;

				x10 = y0; x11 = y1; x12 = y2; x13 = y3;
				x14 = y4; x15 = y5; x16 = y6; x17 = y7;
				x18 = y8; x19 = y9; x1A = yA; x1B = yB;
				x1C = yC; x1D = yD; x1E = yE; x1F = yF;
			}

			state[0] = x00; state[1] = x01; state[2] = x02; state[3] = x03;
			state[4] = x04; state[5] = x05; state[6] = x06; state[7] = x07;
			state[8] = x08; state[9] = x09; state[10] = x0A; state[11] = x0B;
			state[12] = x0C; state[13] = x0D; state[14] = x0E; state[15] = x0F;
			state[16] = x10; state[17] = x11; state[18] = x12; state[19] = x13;
			state[20] = x14; state[21] = x15; state[22] = x16; state[23] = x17;
			state[24] = x18; state[25] = x19; state[26] = x1A; state[27] = x1B;
			state[28] = x1C; state[29] = x1D; state[30] = x1E; state[31] = x1F;
		}

	}
}
