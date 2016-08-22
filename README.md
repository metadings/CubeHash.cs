
**﻿﻿CubeHash.cs source code package - C# implementation**

```
2016-08-19
Uli Riehm <metadings@live.de>
Public Domain

Based on supercop-20141124/crypto_hash/cubehash512/unrolled
     and supercop-20141124/crypto_hash/cubehash512/unrolled3

20100623, 20100917
D. J. Bernstein
Public domain.
```

Ask questions on [stackoverflow](http://stackoverflow.com/questions/tagged/c%23+cubehash) using tags `C#``CubeHash` !

**Usage 1**

Have "one" CubeHash value.

```csharp
using Crypto;
using System;
using System.Text;


	string text = "HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT";
	byte[] bytes = Encoding.UTF8.GetBytes(text);
	byte[] value;

	using (var hash = new CubeHash512()) value = hash.ComputeHash(bytes);

	foreach (byte v in value) Console.Write("{0:x2}", v);
	Console.WriteLine();

```

**Usage 2**

Have "many" CubeHash values.

```csharp
using Crypto;
using System;
using System.Text;


	byte[] textBytes = Encoding.UTF8.GetBytes("HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT");

	byte[] hashSource = new byte[sizeof(UInt32) + textBytes.Length];
	Buffer.BlockCopy(textBytes, 0, hashSource, sizeof(UInt32), textBytes.Length);

	var hashValue = new byte[64];

	UInt32 i = 0; // threadI;

	using (var hash = new CubeHash512())
	{
		do
		{
			CubeHash.UInt32ToBytes(i, hashSource, 0);

			hash.Compute(hashValue, hashSource);

			// if (Quersumme(i + 1) == 1) Console.WriteLine ...

		} while (0 < ++i);

		/* Beware. Your program will run FOR HOURS !

		   2016-08-21 13.46.00
		   Intel Pentium Dual CPU E2160 @ 1.80GHz x2

		     100.000.000 CubeHash512 in 14min 08sec
		   ==  100000000 ÷ (14×60 + 08)
		   :=    117.925 CubeHash512/s

		1. Run this using a pipe, on GNU/Linux and on Windows

		   $ mono ./YourProgram.exe > './YourPrograms output.txt'

		2. Use `emacs` as your editor.

		   Press `M-x auto-revert-mode`
		   or use file `~/.emacs.d/init.el` with `(global-auto-revert-mode 1)`,

		   to have a real-time view of your program.

		3. Also try this using new System.Threading.Thread's:

		} while (threadI < (i += threadC)); /**/
	}

	foreach (byte v in hashValue) Console.Write("{0:x2}", v);
	Console.WriteLine();

```

**Example 1**

```
~/CubeHash.cs/bin/Debug $ echo -n HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT > ./Hallo.txt

~/CubeHash.cs/bin/Debug $ hexdump ./Hallo.txt 
0000000 4848 4848 4141 4141 4c4c 4c4c 4f4f 4f4f
0000010 5757 5757 4545 4545 4c4c 4c4c 5454 5454
0000020

~/CubeHash.cs/bin/Debug $ mono ./CubeHash.exe --in=./Hallo.txt
d639ca075ead8012be6ce25f8de10f51081ec20f8626f60c2ffebcf74a179af1731ac3e2cddbe742cfc9049b116cb4c4e3d318317e47d01d27e2de7c1f5b56da
```

