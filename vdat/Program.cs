using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace vdat
{
    class Program
    {
        #region vars
        private static  byte[] key, iv;
        private static  byte[] indexivsha1 = { 0xE9, 0x7B, 0xE9, 0x46, 0x8A, 0x0F, 0xD5, 0x45, 0xE4, 0x03, 0xFB, 0xA6, 0x2A, 0x55, 0xA4, 0xDF, 0x9D, 0xBC, 0xD3, 0x98 };
        private static byte[] indexlowerkeysha1 = { 0x15, 0x5E, 0x72, 0xC8, 0xC4, 0xA2, 0xA4, 0x7B, 0x8F, 0x8F, 0x9D, 0x3C, 0x23, 0x35, 0x81, 0x6A, 0x19, 0x40, 0xD5, 0x92 };
        private static byte[] indexhigherkeysha1 = { 0x31, 0x12, 0x13, 0x95, 0x30, 0xEC, 0x62, 0x70, 0xCA, 0xB0, 0x45, 0x2A, 0x1C, 0x5F, 0x5D, 0xFD, 0xBE, 0xFD, 0x2D, 0x27 };
        private static string kpath = @"C:\vitakeys\";
        #endregion vars

        /// <summary>
        /// This variable is used to read into it for the ReadWriteData()
        /// </summary>
        private static byte[] readBuffer = new byte[0];

        /// <summary>
        /// Used as counter for the Progress bar to know that a full buffer would be written
        /// </summary>
        private static long progressCounter = 0;

        /// <summary>
        /// Used to know if a custom progress byte counter shall be used as temporary input
        /// </summary>
        private static bool IsCustomProgressCounter = false;

        /// <summary>
        /// Used to get the custom progressed byte count
        /// </summary>
        private static long customProgressCounter = 0;

        /// <summary>
        /// Used to know if all operations are done and no new bytes will be counted so we can tell the progress bar to count patterns and such if the counted value do not match the file size to work and generelly to activate custom counting in the reader/writer routine.
        /// </summary>
        private static bool IsProcessRunning = false;

        /// <summary>
        /// Used to know if a custom progress byte counter shall be used as temporary input
        /// </summary>
        private static bool IsCustomFileCounting = false;

        /// <summary>
        /// Used for the progress bar to know that a file would be processed
        /// </summary>
        private static int progressFileCounter = 0;

        /// <summary>
        /// Compare Byte by Byte or Array by Array
        /// </summary>
        /// <param name="bA1">Byte Array 1</param>
        /// <param name="bA2">Byte Array 2</param>
        /// <returns>True if both Byte Array's do match</returns>
        private static bool CompareBytes(byte[] bA1, byte[] bA2)
        {
            int s = 0;
            for (int z = 0; z < bA1.Length; z++)
            {
                if (bA1[z] != bA2[z])
                    s++;
            }

            if (s == 0)
                return true;

            return false;
        }

        /// <summary>
        /// Convert a Byte Array to a Hex String (or a Array of), can be aligned to a specific digi.
        /// </summary>
        /// <param name="array">The Byte Array to Convert to a Hex String</param>
        /// <param name="align">Do we want to aling the Hex String to a specific Length?</param>
        /// <returns>The Hex String</returns>
        private static string[] ByteToString(byte[] array, [Optional]int align)
        {
            string hexString = "  0x";
            string[] hexStringArray = new string[64];
            int count = 0, r = 0;

            for (int i = 0; i < array.Length; i++)
            {
                hexString += array[i].ToString("X2");
                if (align != 0)
                {
                    count++;
                    if (count == align - 1)
                    {
                        hexStringArray[r] = hexString;
                        hexString = "";
                        hexString = "  0x";
                        r++;
                        count = 0;
                    }
                }
            }
            Array.Resize(ref hexStringArray, r);
            return hexStringArray;
        }

        /// <summary>
        /// Show Version and such....
        /// </summary>
        private static void ShowVersion()
        {
            Console.WriteLine("\n vdat - Vita dat Tool v0.1\n  by cfwprophet\n   Special Greets and THX: Hykem & Proxima !!\n    for the index.dat keys(set) and for sharing on psvita devwiki\n");
        }

        /// <summary>
        /// Show Help Screen
        /// </summary>
        private static void ShowUsage()
        {
            Console.WriteLine(" Usage: vdat.exe <option> <type> <version> <input_file>\n\n");
            Console.WriteLine(" <option>              -d = decrypt a dat file");
            Console.WriteLine("                       -e = Encrypt a dat file");
            Console.WriteLine("                       -h = Show this Help screen");
            Console.WriteLine(" <type>         eg. index = type of input file. To time only index is supported");
            Console.WriteLine(" <version>      eg.   100 = The version of the key files to use");
            Console.WriteLine(" <input>            *.dat = The input dat file\n\n");
        }

        /// <summary>
        /// Do we have valid input?
        /// </summary>
        /// <param name="args">The arguments entered</param>
        /// <returns>True if the Input is valid else False</returns>
        private static bool CheckInput(string[] args)
        {
            if (args != null && args.Length != 0 && args.Length < 2 && args[0] == "-h")
            {
                ShowUsage();
            }
            else if (args == null || args.Length == 0 || args.Length < 4 || args[0] != "-d" && args[0] != "-e" || args[1] != "index" || args[2] != "100" && args[2] != "180")
            {
                Console.WriteLine(" Wrong input!\n");
                return false;
            }
            else if (!File.Exists(args[3]))
            {
                Console.WriteLine(" Can not find/access file!\n");
                return false;
                
            }
            else if (!Directory.Exists(kpath))
            {
                Console.WriteLine(@" Can not find/access 'C:\vitakeys\' folder\n");
                return false;
            }

            Console.WriteLine("File --> OK\n\nArguments --> OK\n\nFolder 'vitakeys' --> OK\n");
            return true;
        }

        /// <summary>
        /// Get Keys and load into buffer
        /// </summary>
        /// <param name="type">The Type of the Key like eg. 'index'</param>
        /// <param name="version">The version of the Key eg. '100' for eg. index keys above or euqal to FW Version 1.00 or '180' for eg. index keys above or euqal to FW Version 1.80</param>
        /// <returns>True if the Keys are found and CheckKeys() Cast return also True. Else False</returns>
        private static bool GetKeys(string type, string version)
        {
            key = null;
            iv = null;
            string skey = type + "-key-" + version;
            string siv = type + "-iv-" + version;
            FileInfo fikey = new FileInfo(kpath + skey);
            FileInfo fiiv = new FileInfo(kpath + siv);
            
            if (!File.Exists(kpath + skey))
            {
                Console.WriteLine("Path of " + skey + " --> Not OK\nCan not find key file for: " + skey);
                return false;
            }
            Console.WriteLine("Path of " + skey + " --> OK\n");
            
            if (!File.Exists(kpath + siv))
            {
                Console.WriteLine("Path of " + siv + " --> Not OK\nCan not find key file for: " + siv);
                return false;
            }
            Console.WriteLine("Path of " + siv + " --> OK\n");
            
            if (fikey.Length != 32)
            {
                Console.WriteLine("Length of erk --> Not OK\nThe size of " + skey + " is not alligned to 32 bytes");
                return false;
            }
            Console.WriteLine("Length of erk --> OK\n");
            
            if (fiiv.Length != 16)
            {
                Console.WriteLine("Length of iv --> Not OK\nThe size of " + siv + " is not alligned to 16 bytes");
                return false;
            }
            Console.WriteLine("Length of iv --> OK\n");
            
            using (BinaryReader br = new BinaryReader(File.Open(kpath + skey, FileMode.Open)))
                br.Read(key = new byte[32], 0, 32);
            using (BinaryReader br = new BinaryReader(File.Open(kpath + siv, FileMode.Open)))
                br.Read(iv = new byte[16], 0, 16);
            Console.WriteLine("Load keys into buffer --> OK\n");

            if (!CheckKeys(version))
                return false;

            return true;
        }

        /// <summary>
        /// Do we use valid Keys?
        /// </summary>
        /// <param name="version">The version of the Key</param>
        /// <returns>True if the Hash of your Keys do match the knowen Hash. Else False</returns>
        private static bool CheckKeys(string version)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            byte[] keysha = sha1.ComputeHash(key);
            byte[] ivsha = sha1.ComputeHash(iv);
            byte[] toCompare;

            if (version == "100")
                toCompare = indexlowerkeysha1;
            else
                toCompare = indexhigherkeysha1;
            
            if (!CompareBytes(keysha, toCompare))
            {
                Console.WriteLine("SHA1 of erk --> Not OK\n");
                return false;
            }
            Console.WriteLine("SHA1 of erk --> OK\n");
            
            if (!CompareBytes(ivsha, indexivsha1))
            {
                Console.WriteLine("SHA1 of iv --> Not OK\n");
                return false;
            }
            Console.WriteLine("SHA1 of iv --> OK\n");

            return true;
        }

        /// <summary>
        /// Kombinated Command for Read or Write Binary or Integer Data
        /// </summary>
        /// <param name="fileToUse">The File that will be used to Read from or to Write to it</param>
        /// <param name="fileToUse2">This is used for the "both" methode. fileToUse will be the file to read from and fileToUse2 will be the file to write to it.</param>
        /// <param name="methodReadOrWriteOrBoth">Defination for Read "r" or Write "w" or if you have big data just use Both "b"</param>
        /// <param name="methodBinaryOrInteger">Defination for Binary Data (bin) or Integer Data (int) when write to a file</param>
        /// <param name="binData">byte array of the binary data to read or write</param>
        /// <param name="binData2">integer array of the integer data to read or write</param>
        /// <param name="offset">Otional, used for the "both" methode to deffine a offset to start to read from a file. If you do not wan't to read from the begin use this var to tell the Routine to jump to your deffined offset.</param>
        /// <param name="count">Optional, also used for the "both" methode to deffine to only to read a specific byte count and not till the end of the file.</param>
        private static void ReadWriteData(string fileToUse, [Optional] string fileToUse2, string methodReadOrWriteOrBoth, [Optional] string methodBinaryOrInteger, [Optional] byte[] binData, [Optional] int binData2, [Optional] long offset, [Optional] long count)
        {
            string caseSwitch = methodReadOrWriteOrBoth;
            switch (caseSwitch)
            {
                case "r":
                    {
                        FileInfo fileInfo = new FileInfo(fileToUse);
                        readBuffer = new byte[fileInfo.Length];
                        using (BinaryReader b = new BinaryReader(new FileStream(fileToUse, FileMode.Open, FileAccess.Read)))
                        {
                            b.Read(readBuffer, 0, readBuffer.Length);
                            b.Close();
                        }
                    }
                    break;
                case "w":
                    {
                        using (BinaryWriter b = new BinaryWriter(new FileStream(fileToUse, FileMode.Append, FileAccess.Write)))
                        {
                            caseSwitch = methodBinaryOrInteger;
                            switch (caseSwitch)
                            {
                                case "bin":
                                    {
                                        b.Write(binData, 0, binData.Length);
                                        b.Close();
                                    }
                                    break;
                                case "int":
                                    {
                                        b.Write(binData2);
                                        b.Close();
                                    }
                                    break;
                            }
                        }
                    }
                    break;
                case "b":
                    {   // For data that will cause a buffer overflow we use this method. We read from a Input File and Write to a Output File with the help of a Buffer till the end of file or the specified length is reached.
                        using (BinaryReader br = new BinaryReader(new FileStream(fileToUse, FileMode.Open, FileAccess.Read)))
                        {
                            using (BinaryWriter bw = new BinaryWriter(new FileStream(fileToUse2, FileMode.Append, FileAccess.Write)))
                            {
                                // this is a variable for the Buffer size. Play arround with it and maybe set a new size to get better result's
                                int workingBufferSize = 4096; // high
                                // int workingBufferSize = 2048; // middle
                                // int workingBufferSize = 1024; // default
                                // int workingBufferSize = 128;  // minimum

                                // Do we read data that is smaller then our working buffer size?
                                if (count < workingBufferSize)
                                {
                                    workingBufferSize = (int)count;

                                    // Shall we use byte exact counting for the progress bar?
                                    if (IsProcessRunning)
                                    {
                                        // Tell the Progress Bar our custom setting
                                        IsCustomProgressCounter = true;
                                        customProgressCounter += count;
                                    }
                                }

                                byte[] buffer = new byte[workingBufferSize];
                                int len;

                                // Do we use a specific offset?
                                if (offset != 0)
                                    br.BaseStream.Seek(offset, SeekOrigin.Begin);

                                // Run the process in a loop
                                while ((len = br.Read(buffer, 0, workingBufferSize)) != 0)
                                {
                                    bw.Write(buffer, 0, len);

                                    // We tell the progress bar that we just have wrote 4096 bytes to a file
                                    progressCounter += 1;

                                    // Do we read a specific length?
                                    if (count != 0)
                                    {
                                        // Subtract the working buffer size from the byte count to read/write.
                                        count -= workingBufferSize;

                                        // Stop the loop when the specified byte count to read/write is reached.
                                        if (count == 0)
                                            break;

                                        // When the count value is lower then the working buffer size we set the working buffer to the value of the count variable to not read more data as wanted
                                        if (count < workingBufferSize)
                                        {
                                            workingBufferSize = (int)count;

                                            // Shall we use byte exact counting for the progress bar?
                                            if (IsProcessRunning)
                                            {
                                                // Tell the Progress Bar our custom setting
                                                IsCustomProgressCounter = true;
                                                customProgressCounter += count;
                                            }
                                        }
                                    }
                                }

                                // Do we use custom file counting?
                                if (IsCustomFileCounting)
                                    // Tell the progress bar that one file of a SLB2 container would be extracted
                                    progressFileCounter += 1;

                                bw.Close();
                            }
                            br.Close();
                        }
                    }
                    break;
            }
        }

        /// <summary>
        /// Encrypt Byte Data using AES-CBC and a key & IV
        /// </summary>
        /// <param name="clearData">The 'Clear' not Encrypted Data</param>
        /// <returns>The Encrypted Data</returns>
        private static byte[] AESCBCEncryptByte(byte[] clearData)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                Rijndael algo = Rijndael.Create();

                algo.Key = key;
                algo.IV = iv;
                algo.Mode = CipherMode.CBC;
                algo.Padding = PaddingMode.ISO10126;

                using (CryptoStream cs = new CryptoStream(ms, algo.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        cs.Write(clearData, 0, clearData.Length);
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                    catch (CryptographicException e)
                    {
                        Console.WriteLine("An Error occurred: {0}", e.Message);
                    }
                }

                byte[] encryptedData = ms.ToArray();
                return encryptedData;
            }
        }

        /// <summary>
        /// Decrypt Byte Data using AES-CBC and a key & IV
        /// </summary>
        /// <param name="cipherData">The Encrypted Data</param>
        /// <returns>The 'Clear' Decrypted Data</returns>
        private static byte[] AESCBCDecryptByte(byte[] cipherData)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                Rijndael algo = Rijndael.Create();

                algo.Key = key;
                algo.IV = iv;
                algo.Mode = CipherMode.CBC;
                algo.Padding = PaddingMode.ISO10126;

                using (CryptoStream cs = new CryptoStream(ms, algo.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        cs.Write(cipherData, 0, cipherData.Length);
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                    catch (CryptographicException e)
                    {
                        Console.WriteLine("An Error occurred: {0}", e.Message);
                    }
                }

                byte[] decryptedData = ms.ToArray();
                return decryptedData;
            }
        }

        // Main entry point
        static void Main(string[] args)
        {
            ShowVersion();
            if (!CheckInput(args))
            {
                ShowUsage();
                Console.ReadLine();
                Environment.Exit(0);
            }

            if (!GetKeys(args[1], args[2]))
                Environment.Exit(0);

            ReadWriteData(args[3], null, "r");
            if (readBuffer == null)
            {
                Console.WriteLine("Read Buffer is empty!\nSomething went wrong");
                Environment.Exit(0);
            }
            Console.WriteLine("Data Readed into Buffer --> OK\n");


            byte[] deencrypted = null;
            if (args[0] == "-d")
            {
                if (args[1] == "index")
                {
                    deencrypted = AESCBCDecryptByte(readBuffer);

                    if (deencrypted != null)
                        Console.WriteLine("Data Decrypted --> OK\n");

                    if (File.Exists("index.txt"))
                        File.Delete("index.txt");

                    byte[] textArray = null;
                    Buffer.BlockCopy(deencrypted, 0x20, textArray = new byte[deencrypted.Length - 32], 0, deencrypted.Length - 32);
                    File.WriteAllBytes("index.txt", textArray);

                    if (File.Exists("index.txt"))
                        Console.WriteLine("Writing Decrypted Data to Text --> OK\n");
                    else
                        Console.WriteLine("Writing Decrypted Data to Text --> Not OK!\nCan't access/find the file.");

                    if (File.Exists("out.bin"))
                        File.Delete("out.bin");

                    ReadWriteData("out.bin", null, "w", "bin", deencrypted);

                    if (File.Exists("out.bin"))
                        Console.WriteLine("Writing Decrypted Data to Binary --> OK");
                    else
                        Console.WriteLine("Writing Decrypted Data to Binary --> Not OK!\nCan't access/find the file.");
                }
            }
            else if (args[0] == "-e")
            {
                if (args[1] == "index")
                {
                    SHA256 sha256 = new SHA256CryptoServiceProvider();
                    byte[] hashed = sha256.ComputeHash(readBuffer);

                    if (hashed != null)
                        Console.WriteLine("Computing Hash of index.txt --> OK\n");
                    else
                        Console.WriteLine("Computing Hash of index.txt --> Not OK\n");

                    byte[] hashedBlock = new byte[hashed.Length + readBuffer.Length];
                    Buffer.BlockCopy(hashed, 0, hashedBlock, 0, hashed.Length);
                    Buffer.BlockCopy(readBuffer, 0, hashedBlock, hashed.Length, readBuffer.Length);

                    if (hashedBlock != null)
                        Console.WriteLine("Generating new Block with SHA256 Hash and index.txt --> OK\n");
                    else
                        Console.WriteLine("Generating new Block with SHA256 Hash and index.txt --> Not OK\n");

                    string[] text = ByteToString(hashedBlock, 16);
                    Console.WriteLine("New Generated Hashed Block:\n");
                    foreach (string str in text)
                        Console.WriteLine(str);
                    Console.WriteLine("");

                    deencrypted = AESCBCEncryptByte(hashedBlock);

                    if (deencrypted != null)
                        Console.WriteLine("Data Encrypted --> OK\n");

                    if (File.Exists("new_index.dat"))
                        File.Delete("new_index.dat");

                    ReadWriteData("new_index.dat", null, "w", "bin", deencrypted);

                    if (File.Exists("new_index.dat"))
                        Console.WriteLine("Writing Encrypted Data to Binary --> OK");
                    else
                        Console.WriteLine("Writing Encrypted Data to Binary --> Not OK!\nCan't access/find the file.");
                }
            }

            Environment.Exit(0);
        }
    }
}
