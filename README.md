
**﻿﻿CubeHash.cs source code package - C# implementation**

```
Written in 2016 by Uli Riehm <metadings@live.de>

To the extent possible under law, the author(s) have dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with
this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

Based on supercop-20141124/crypto_hash/cubehash512/unrolled:

20100623
D. J. Bernstein
Public domain.

Implementation strategy suggested by Scott McMurray.

Based on supercop-20141124/crypto_hash/cubehash512/unrolled3:

20100917
D. J. Bernstein
Public domain.

Compressed version of unrolled2, plus better locality in inner loop.
```

Ask questions on [stackoverflow](http://stackoverflow.com/questions/tagged/c%23+cubehash) using tags `C#``CubeHash` !

**Usage 1**

Have "one" CubeHash hash value.

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

Have "many" CubeHash hash values.

```csharp
using Crypto;
using System;
using System.Text;


	byte[] textBytes = Encoding.UTF8.GetBytes("HHHHAAAALLLLOOOOWWWWEEEELLLLTTTT");

	byte[] hashSource = new byte[sizeof(UInt32) + textBytes.Length];
	Buffer.BlockCopy(textBytes, 0, hashSource, sizeof(UInt32), textBytes.Length);

	var hashValue = new byte[64];

	UInt32 i = 0; // threadI;

	using (var hash = new CubeHash())
	{
		do
		{
			CubeHash.UInt32ToBytes(i, hashSource, 0);

			hash.Compute(hashValue, hashSource);

			// if (Quersumme(i + 1) == 1) Console.WriteLine ...

		} while (0 < ++i);

		/* DANGER: Your program will run FOR HOURS !

		   Intel Pentium Dual CPU E2160 @ 1.80GHz x2
		   => 100.000.000 CubeHash512 in 954s or 15,9m
		   => 104.821 CubeHash512/s or 6.289.308 CubeHash512/m

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
b20920f4f54757f981cd182722e89bd3f6d5b634c80402e5fdfcf5d0e25512d81700a5dac501720c8393063ac597f1b1ff760c4f12197874f657f75ddd8bffda
```

