using System;
using System.Diagnostics;

namespace Crypto
{
    public class CubeHash224 : CubeHash { public CubeHash224() : base(224) { } }

    public class CubeHash256 : CubeHash { public CubeHash256() : base(256) { } }

	public class CubeHash384 : CubeHash { public CubeHash384() : base(384) { } }

	public class CubeHash512 : CubeHash { public CubeHash512() : base(512) { } }

    public class CubeHash : IDisposable
	{
		public static uint BytesToUInt32(byte[] buffer, int offset)
		{
			return
				((uint)buffer[offset + 3] << 3 * 8) |
				((uint)buffer[offset + 2] << 2 * 8) |
				((uint)buffer[offset + 1] << 1 * 8) |
				((uint)buffer[offset]);
		}

		public static void UInt32ToBytes(uint value, byte[] buffer, int offset)
		{
			buffer[offset + 3] = (byte)(value >> 3 * 8);
			buffer[offset + 2] = (byte)(value >> 2 * 8);
			buffer[offset + 1] = (byte)(value >> 1 * 8);
			buffer[offset] = (byte)value;
		}

		private readonly int hashSize;

		public virtual int HashSize { get { return hashSize; } }

		public const int BlockSizeInBytes = 32;

		public const int ROUNDS = 16;

		private readonly byte[] buffer = new byte[BlockSizeInBytes * 16];

		private int bufferFilled;

		private readonly uint[] state = new uint[BlockSizeInBytes];

		public CubeHash() : this(512) { }

		// public CubeHash(int hashSize) : this (hashSize, 256) { }

		public CubeHash(int hashSize) // , int blockSize)
		{
			this.hashSize = hashSize / 8;
			// _blockSize = blockSize;
        }

		private bool _isInitialized = false;

		public virtual void Initialize()
		{
			Clear();

			state[00] = (uint)HashSize / 8;
			state[01] = BlockSizeInBytes;
			state[02] = ROUNDS;

			TransformBlock();

			_isInitialized = true;
		}

		public void Dispose() { Dispose(true); }

		protected virtual void Dispose(bool disposing) { if (disposing) Clear(); }

		public virtual void Clear()
		{
			_isInitialized = false;

			for (int i = 0; i < 32; ++i) state[i] = 0U;
			for (int i = 0; i < buffer.Length; ++i) buffer[i] = 0x00;
			bufferFilled = 0;
		}

		public virtual void Core(byte[] array, int start, int count)
		{
			if (!_isInitialized) Initialize();

			int bytesDone = 0, bytesToFill;
			int blocksDone, blockBytesDone;
			int i; // uint u;
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
						for (i = bufferFilled; i < buffer.Length; ++i) buffer[i] = 0x00;
					}
				}

			} while (bytesDone < count);
		}

		public virtual byte[] Final()
        {
			var result = new byte[HashSize];
			Final(result);
			return result;
		}

		public virtual void Final(byte[] result)
		{
			if (!_isInitialized) Initialize();

/*
	u = (128 >> (state->pos % 8));
	u <<= 8 * ((state->pos / 8) % 4);
	state->x[state->pos / 32] ^= u; /**/

			for (int i = bufferFilled; i < buffer.Length; ++i) buffer[i] = 0x00;
			TransformBlock();

			state[31] ^= 1;

			TransformBlock();
			TransformBlock();

			// if (BitConverter.IsLittleEndian)
			Buffer.BlockCopy(state, 0, result, 0, HashSize);

			_isInitialized = false;
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

		static uint ROTATE(uint a, int b) { return ((a << b) | (a >> (32 - b))); }

		protected virtual void TransformBlock()
		{
			TransformBlock(null, 0);
		}

		protected virtual void TransformBlock(byte[] data, int start)
        {
			if (data != null)
			{
				for (int i = 0; i < (32 / 4); i++)
					state[i] ^= data[start + i];
			}

			uint state00 = state[0];
			uint state01 = state[1];
			uint state02 = state[2];
			uint state03 = state[3];
			uint state04 = state[4];
			uint state05 = state[5];
			uint state06 = state[6];
			uint state07 = state[7];
			uint state08 = state[8];
			uint state09 = state[9];
			uint state0A = state[10];
			uint state0B = state[11];
			uint state0C = state[12];
			uint state0D = state[13];
			uint state0E = state[14];
			uint state0F = state[15];
			uint state10 = state[16];
			uint state11 = state[17];
			uint state12 = state[18];
			uint state13 = state[19];
			uint state14 = state[20];
			uint state15 = state[21];
			uint state16 = state[22];
			uint state17 = state[23];
			uint state18 = state[24];
			uint state19 = state[25];
			uint state1A = state[26];
			uint state1B = state[27];
			uint state1C = state[28];
			uint state1D = state[29];
			uint state1E = state[30];
			uint state1F = state[31];

			uint y0;
			uint y1;
			uint y2;
			uint y3;
			uint y4;
			uint y5;
			uint y6;
			uint y7;
			uint y8;
			uint y9;
			uint yA;
			uint yB;
			uint yC;
			uint yD;
			uint yE;
			uint yF;

            for (int r = 0; r < ROUNDS; ++r)
            {
                state10 += state00;
                state11 += state01;
                state12 += state02;
                state13 += state03;
                state14 += state04;
                state15 += state05;
                state16 += state06;
                state17 += state07;
                state18 += state08;
                state19 += state09;
                state1A += state0A;
                state1B += state0B;
                state1C += state0C;
                state1D += state0D;
                state1E += state0E;
                state1F += state0F;

                y8 = state00;
                y9 = state01;
				yA = state02;
                yB = state03;
                yC = state04;
                yD = state05;
                yE = state06;
                yF = state07;
                y0 = state08;
                y1 = state09;
                y2 = state0A;
                y3 = state0B;
                y4 = state0C;
                y5 = state0D;
                y6 = state0E;
                y7 = state0F;

				state00 = ROTATE(y0, 7);
				state01 = ROTATE(y1, 7);
				state02 = ROTATE(y2, 7);
				state03 = ROTATE(y3, 7);
				state04 = ROTATE(y4, 7);
				state05 = ROTATE(y5, 7);
				state06 = ROTATE(y6, 7);
				state07 = ROTATE(y7, 7);
				state08 = ROTATE(y8, 7);
				state09 = ROTATE(y9, 7);
				state0A = ROTATE(yA, 7);
				state0B = ROTATE(yB, 7);
				state0C = ROTATE(yC, 7);
				state0D = ROTATE(yD, 7);
				state0E = ROTATE(yE, 7);
				state0F = ROTATE(yF, 7);

                state00 ^= state10;
                state01 ^= state11;
                state02 ^= state12;
                state03 ^= state13;
                state04 ^= state14;
                state05 ^= state15;
                state06 ^= state16;
                state07 ^= state17;
                state08 ^= state18;
                state09 ^= state19;
                state0A ^= state1A;
                state0B ^= state1B;
                state0C ^= state1C;
                state0D ^= state1D;
                state0E ^= state1E;
                state0F ^= state1F;

                y2 = state10;
                y3 = state11;
                y0 = state12;
                y1 = state13;
                y6 = state14;
                y7 = state15;
                y4 = state16;
                y5 = state17;
                yA = state18;
                yB = state19;
                y8 = state1A;
                y9 = state1B;
                yE = state1C;
                yF = state1D;
                yC = state1E;
                yD = state1F;

                state10 = y0;
                state11 = y1;
                state12 = y2;
                state13 = y3;
                state14 = y4;
                state15 = y5;
                state16 = y6;
                state17 = y7;
                state18 = y8;
                state19 = y9;
                state1A = yA;
                state1B = yB;
                state1C = yC;
                state1D = yD;
                state1E = yE;
                state1F = yF;

                state10 += state00;
                state11 += state01;
                state12 += state02;
                state13 += state03;
                state14 += state04;
                state15 += state05;
                state16 += state06;
                state17 += state07;
                state18 += state08;
                state19 += state09;
                state1A += state0A;
                state1B += state0B;
                state1C += state0C;
                state1D += state0D;
                state1E += state0E;
                state1F += state0F;

                y4 = state00;
                y5 = state01;
                y6 = state02;
                y7 = state03;
                y0 = state04;
                y1 = state05;
                y2 = state06;
                y3 = state07;
                yC = state08;
                yD = state09;
                yE = state0A;
                yF = state0B;
                y8 = state0C;
                y9 = state0D;
                yA = state0E;
                yB = state0F;

				state00 = ROTATE(y0, 11);
				state01 = ROTATE(y1, 11);
				state02 = ROTATE(y2, 11);
				state03 = ROTATE(y3, 11);
				state04 = ROTATE(y4, 11);
				state05 = ROTATE(y5, 11);
				state06 = ROTATE(y6, 11);
				state07 = ROTATE(y7, 11);
				state08 = ROTATE(y8, 11);
				state09 = ROTATE(y9, 11);
				state0A = ROTATE(yA, 11);
				state0B = ROTATE(yB, 11);
				state0C = ROTATE(yC, 11);
				state0D = ROTATE(yD, 11);
				state0E = ROTATE(yE, 11);
				state0F = ROTATE(yF, 11);

                state00 ^= state10;
                state01 ^= state11;
                state02 ^= state12;
                state03 ^= state13;
                state04 ^= state14;
                state05 ^= state15;
                state06 ^= state16;
                state07 ^= state17;
                state08 ^= state18;
                state09 ^= state19;
                state0A ^= state1A;
                state0B ^= state1B;
                state0C ^= state1C;
                state0D ^= state1D;
                state0E ^= state1E;
                state0F ^= state1F;

                y1 = state10;
                y0 = state11;
                y3 = state12;
                y2 = state13;
                y5 = state14;
                y4 = state15;
                y7 = state16;
                y6 = state17;
                y9 = state18;
                y8 = state19;
                yB = state1A;
                yA = state1B;
                yD = state1C;
                yC = state1D;
                yE = state1E;
                yF = state1F;

                state10 = y0;
                state11 = y1;
                state12 = y2;
                state13 = y3;
                state14 = y4;
                state15 = y5;
                state16 = y6;
                state17 = y7;
                state18 = y8;
                state19 = y9;
                state1A = yA;
                state1B = yB;
                state1C = yC;
                state1D = yD;
                state1E = yE;
                state1F = yF;
            }

			state[0] = state00;
			state[1] = state01;
			state[2] = state02;
			state[3] = state03;
			state[4] = state04;
			state[5] = state05;
			state[6] = state06;
			state[7] = state07;
			state[8] = state08;
			state[9] = state09;
			state[10] = state0A;
			state[11] = state0B;
			state[12] = state0C;
			state[13] = state0D;
			state[14] = state0E;
			state[15] = state0F;
			state[16] = state10;
			state[17] = state11;
			state[18] = state12;
			state[19] = state13;
			state[20] = state14;
			state[21] = state15;
			state[22] = state16;
			state[23] = state17;
			state[24] = state18;
			state[25] = state19;
			state[26] = state1A;
			state[27] = state1B;
			state[28] = state1C;
			state[29] = state1D;
			state[30] = state1E;
			state[31] = state1F;
        }

    }
}
