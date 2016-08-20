/*	CubeHash.cs source code package - C# implementation

	2016-08-19
	Uli Riehm <metadings@live.de>
	Public Domain

	Based on supercop-20141124/crypto_hash/cubehash512/unrolled
	     and supercop-20141124/crypto_hash/cubehash512/unrolled3

	20100623, 20100917
	D. J. Bernstein
	Public domain.
*/
using System;
using System.Security.Cryptography;

namespace Crypto
{
	public class CubeHash224 : CubeHash { public CubeHash224() : base(224) { } }

	public class CubeHash256 : CubeHash { public CubeHash256() : base(256) { } }

	public class CubeHash384 : CubeHash { public CubeHash384() : base(384) { } }

	public class CubeHash512 : CubeHash { public CubeHash512() : base(512) { } }

	public class CubeHash : HashAlgorithm // IDisposable
	{
		public static uint BytesToUInt32(byte[] buffer, int offset)
		{
			return
				((uint)buffer[offset + 3] << 24) |
				((uint)buffer[offset + 2] << 16) |
				((uint)buffer[offset + 1] << 8) |
				((uint)buffer[offset]);
		}

		public static void UInt32ToBytes(uint value, byte[] buffer, int offset)
		{
			buffer[offset + 3] = (byte)(value >> 24);
			buffer[offset + 2] = (byte)(value >> 16);
			buffer[offset + 1] = (byte)(value >> 8);
			buffer[offset] = (byte)value;
		}

		private readonly int hashSize;

		public override int HashSize { get { return hashSize; } }

		public const int BlockSizeInBytes = 32;

		public const int ROUNDS = 16;

		private readonly byte[] buffer = new byte[512];

		private int bufferFilled;

		// private readonly uint[] state = new uint[BlockSizeInBytes];

		public CubeHash() : this(512) { }

		// public CubeHash(int hashSize) : this (hashSize, 256) { }

		public CubeHash(int hashSize) // , int blockSize)
		{
			this.hashSize = hashSize;
			// _blockSize = blockSize;
		}

		private bool isInitialized = false;

		public override void Initialize()
		{
			HashClear();

			x00 = (uint)HashSize / 8;
			x01 = BlockSizeInBytes;
			x02 = ROUNDS;

			TransformBlock();

			isInitialized = true;
		}

		protected override void Dispose(bool disposing) { if (disposing) HashClear(); }

		public virtual void HashClear()
		{
			isInitialized = false;

			x00 = 0U; x01 = 0U; x02 = 0U; x03 = 0U;
			x04 = 0U; x05 = 0U; x06 = 0U; x07 = 0U;
			x08 = 0U; x09 = 0U; x0A = 0U; x0B = 0U;
			x0C = 0U; x0D = 0U; x0E = 0U; x0F = 0U;

			x10 = 0U; x11 = 0U; x12 = 0U; x13 = 0U;
			x14 = 0U; x15 = 0U; x16 = 0U; x17 = 0U;
			x18 = 0U; x19 = 0U; x1A = 0U; x1B = 0U;
			x1C = 0U; x1D = 0U; x1E = 0U; x1F = 0U;

			y0 = 0U; y1 = 0U; y2 = 0U; y3 = 0U;
			y4 = 0U; y5 = 0U; y6 = 0U; y7 = 0U;
			y8 = 0U; y9 = 0U; yA = 0U; yB = 0U;
			yC = 0U; yD = 0U; yE = 0U; yF = 0U;

			for (int i = 0; i < buffer.Length; ++i) buffer[i] = 0x00;
			bufferFilled = 0;
		}

		protected override void HashCore(byte[] array, int start, int count)
		{
			Core(array, start, count);
		}

		public virtual void Core(byte[] array, int start, int count)
		{
			if (!isInitialized) Initialize();

			int bytesDone = 0, bytesToFill;
			int blocksDone, blockBytesDone;
			// uint u;
			do
			{
				bytesToFill = Math.Min(count, buffer.Length - bufferFilled);
				Buffer.BlockCopy(array, start, buffer, bufferFilled, bytesToFill);

				bytesDone += bytesToFill;
				bufferFilled += bytesToFill;
				count -= bytesToFill;
				start += bytesToFill;

				if (bufferFilled >= BlockSizeInBytes)
				{
					for (blocksDone = 0; (blockBytesDone = blocksDone * BlockSizeInBytes) < bufferFilled; ++blocksDone)
					{
/*
	crypto_uint32 u = *data;
	u <<= 8 * ((state->pos / 8) % 4);
	state->x[state->pos / 32] ^= u; /**/

						TransformBlock(buffer, blockBytesDone);
					}
					blockBytesDone = --blocksDone * BlockSizeInBytes;

					bufferFilled -= blockBytesDone;
					if (bufferFilled > 0)
					{
						Buffer.BlockCopy(buffer, blockBytesDone, buffer, 0, bufferFilled);
						// for (int i = bufferFilled; i < buffer.Length; ++i) buffer[i] = 0x00;
					}
				}

			} while (bytesDone < count);
		}

		protected override byte[] HashFinal ()
		{
			return Final();
		}

		public virtual byte[] Final()
		{
			var result = new byte[HashSize / 8];
			Final(result);
			return result;
		}

		public virtual void Final(byte[] result)
		{
			if (!isInitialized) Initialize();

/*
	u = (128 >> (state->pos % 8));
	u <<= 8 * ((state->pos / 8) % 4);
	state->x[state->pos / 32] ^= u; /**/

			buffer[bufferFilled++] = 0x80;
			for (int i = bufferFilled; i < BlockSizeInBytes; ++i) buffer[i] = 0x00;
			TransformBlock(buffer, 0);

			x1F ^= 1;

			TransformBlock();
			TransformBlock();

			// if (BitConverter.IsLittleEndian)

			// for (int i = 0; i < (HashSize / 8); ++i) result[i] = 0x00;

			switch (HashSize)
			{
				case 224:
					UInt32ToBytes(x00, result, 0);
					UInt32ToBytes(x01, result, 4);
					UInt32ToBytes(x02, result, 8);
					UInt32ToBytes(x03, result, 12);
					UInt32ToBytes(x04, result, 16);
					UInt32ToBytes(x05, result, 20);
					UInt32ToBytes(x06, result, 24);
					break;

				case 256:
					UInt32ToBytes(x00, result, 0);
					UInt32ToBytes(x01, result, 4);
					UInt32ToBytes(x02, result, 8);
					UInt32ToBytes(x03, result, 12);
					UInt32ToBytes(x04, result, 16);
					UInt32ToBytes(x05, result, 20);
					UInt32ToBytes(x06, result, 24);
					UInt32ToBytes(x07, result, 28);
					break;

				case 384:
					UInt32ToBytes(x00, result, 0);
					UInt32ToBytes(x01, result, 4);
					UInt32ToBytes(x02, result, 8);
					UInt32ToBytes(x03, result, 12);
					UInt32ToBytes(x04, result, 16);
					UInt32ToBytes(x05, result, 20);
					UInt32ToBytes(x06, result, 24);
					UInt32ToBytes(x07, result, 28);
					UInt32ToBytes(x08, result, 32);
					UInt32ToBytes(x09, result, 36);
					UInt32ToBytes(x0A, result, 40);
					UInt32ToBytes(x0B, result, 44);
					break;

				case 512:
					UInt32ToBytes(x00, result, 0);
					UInt32ToBytes(x01, result, 4);
					UInt32ToBytes(x02, result, 8);
					UInt32ToBytes(x03, result, 12);
					UInt32ToBytes(x04, result, 16);
					UInt32ToBytes(x05, result, 20);
					UInt32ToBytes(x06, result, 24);
					UInt32ToBytes(x07, result, 28);
					UInt32ToBytes(x08, result, 32);
					UInt32ToBytes(x09, result, 36);
					UInt32ToBytes(x0A, result, 40);
					UInt32ToBytes(x0B, result, 44);
					UInt32ToBytes(x0C, result, 48);
					UInt32ToBytes(x0D, result, 52);
					UInt32ToBytes(x0E, result, 56);
					UInt32ToBytes(x0F, result, 60);
					break;

				// default: throw new InvalidOperationException();
			}

			isInitialized = false;
		}

		public virtual void Compute(byte[] value, byte[] sourceCode)
		{
			Core(sourceCode, 0, sourceCode.Length);
			Final(value);
		}

		public virtual byte[] Compute(byte[] sourceCode)
		{
			var value = new byte[HashSize];
			Core(sourceCode, 0, sourceCode.Length);
			Final(value);
			return value;
		}

		// Beware. A ROTATE method would be nice, but this halfes the speed of CubeHash.
		// static uint ROTATE(uint a, int b) { return ((a << b) | (a >> (32 - b))); }

		protected virtual void TransformBlock()
		{
			TransformBlock(null, 0);
		}

		uint x00, x01, x02, x03, x04, x05, x06, x07;
		uint x08, x09, x0A, x0B, x0C, x0D, x0E, x0F;
		uint x10, x11, x12, x13, x14, x15, x16, x17;
		uint x18, x19, x1A, x1B, x1C, x1D, x1E, x1F;

		uint y0, y1, y2, y3, y4, y5, y6, y7;
		uint y8, y9, yA, yB, yC, yD, yE, yF;

		protected virtual void TransformBlock(byte[] data, int start)
		{
			if (data != null)
			{
				x00 ^= BytesToUInt32(data, start);
				x01 ^= BytesToUInt32(data, start + 4);
				x02 ^= BytesToUInt32(data, start + 8);
				x03 ^= BytesToUInt32(data, start + 12);
				x04 ^= BytesToUInt32(data, start + 16);
				x05 ^= BytesToUInt32(data, start + 20);
				x06 ^= BytesToUInt32(data, start + 24);
				x07 ^= BytesToUInt32(data, start + 28);
			}

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
				yD = x1C; yC = x1D; yE = x1E; yF = x1F;

				x10 = y0; x11 = y1; x12 = y2; x13 = y3;
				x14 = y4; x15 = y5; x16 = y6; x17 = y7;
				x18 = y8; x19 = y9; x1A = yA; x1B = yB;
				x1C = yC; x1D = yD; x1E = yE; x1F = yF;
			}
		}

	}
}
