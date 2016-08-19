﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Globalization;

namespace Crypto
{
	internal static class Program
	{
		static void Main(string[] args) 
		{
			int argsI; string command;
			Dictionary<string, string> dictionary = ReadConsoleArguments(args, out argsI, out command);

			if (string.IsNullOrEmpty(command) || command.Equals("CubeHash512", StringComparison.OrdinalIgnoreCase))
			{
				CubeHash512(dictionary);
				return;
			}

			string format =
				"      HELP: ./CubeHash.exe --In=./Hallo.txt -- CubeHash512{0}"
				+	"        ./CubeHash.exe [ --option=value ] [ -- ] [ command ]{0}"
				+	"{0}"
				+	"   COMMAND: CubeHash512{0}"
				+	"            Requires option --In=./FileName.txt.{0}";
			
			Console.WriteLine(format, Environment.NewLine);
		}

		public static void CubeHash512(IDictionary<string, string> dictionary)
		{
			FileInfo inFile = null;
			if (dictionary.ContainsKey("In"))
			if (File.Exists(dictionary["In"]))
				inFile = new FileInfo(dictionary["In"]);
			if (inFile == null || !inFile.Exists)
				throw new FileNotFoundException("In (file) not found");

			/* FileInfo outFile;
			if (dictionary.ContainsKey("Out"))
			if (File.Exists(dictionary["Out"]))
				outFile = new FileInfo(dictionary["Out"]);
			// if (!outFile.Exists) throw new FileNotFoundException("Out (file) not found"); /**/

			/* string inDir = inFile.DirectoryName;
			string inFileName = inFile.Name;
			string inFileExt = inFile.Extension;

			var outFile = new FileInfo(inDir + inFileName + ".Blake2B" + inFileExt);
			/**/

			byte[] hashValue;

			// using (var hash = new CubeHash()) value = hash.ComputeHash(bytes);

			using (var fileIn = new FileStream(inFile.FullName, FileMode.Open))
			// using (var fileOut = new FileStream(outFile.FullName))
			using (var hash = new CubeHash512())
			{
				var buffer = new byte[256];
				int bufferC = 0;
				int bufferL;
				do
				{
					bufferL = fileIn.Read(buffer, bufferC, bufferC + buffer.Length);
				
					if (bufferL > 0)
					{
						hash.Core(buffer, 0, bufferL);
					}
				
				} while(bufferL == 0 || (bufferC += buffer.Length) < fileIn.Length);

				hashValue = hash.Final();
			}

			foreach (byte v in hashValue) Console.Write("{0:x2}", v);
			Console.WriteLine();
		}


		static Dictionary<string, string> ReadConsoleArguments(string[] args, out int argsI, out string command)
		{
			argsI = 0;

			int nameI, dashs;
			string arg, argName;
			var dictionary = new Dictionary<string, string>(StringComparer.CurrentCultureIgnoreCase);
			do
			{
				if (args.Length == 0) break;

				arg = args[argsI];
				nameI = arg.IndexOf('=');
				dashs = arg.StartsWith("--") ? 2 : (arg.StartsWith("-") ? 1 : 0);

				if (dashs > 0)
				{
					if (arg.Length == dashs)
					{
						break;
					}
					if (nameI == -1)
					{
						argName = arg.Substring(dashs);
						dictionary.Add(argName, string.Empty);
						continue;
					}
					else
					{
						argName = arg.Substring(dashs, nameI - dashs);
						arg = arg.Substring(nameI + 1);
						dictionary.Add(argName, arg);
						continue;
					}
				}

				break;
			} while (++argsI < args.Length);

			command = string.Empty;
			if (argsI + 1 < args.Length)
			{
				command = args[++argsI];
			} /**/

			return dictionary;
		}
	}
}

