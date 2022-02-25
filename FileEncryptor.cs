using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

class FileEncryptor
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            _printUsage();
            return;
        }
        switch (args[0])
        {
            case "/encrypt":
                _encrypt2(args[1]);
                break;
            case "/decrypt":
                _decrypt2(args[1]);
                break;
            default:
                _printUsage();
                break;
        }
    }
    static void _encrypt(string filename)
    {
        string tempfile = Path.GetTempFileName();
        FileStream rawInput = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
        FileStream rawOutput = new FileStream(tempfile, FileMode.Open, FileAccess.Write, FileShare.None);

        SymmetricAlgorithm alg = new AesManaged();
        alg.Mode = CipherMode.CBC;
        alg.Padding = PaddingMode.PKCS7;
        alg.GenerateIV();
        _writeIV(alg, rawOutput);

        alg.Key = _keyFromPassword(_getPassword(0));

        Stream cryptOutput = new CryptoStream(rawOutput, alg.CreateEncryptor(), CryptoStreamMode.Write);
        _pump(rawInput, cryptOutput);

        cryptOutput.Close();
        rawInput.Close();
        rawOutput.Close();
        File.Delete(filename);
        File.Move(tempfile, filename);
    }

    static void _decrypt(string filename)
    {
        string tempfile = Path.GetTempFileName();
        FileStream rawInput = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
        FileStream rawOutput = new FileStream(tempfile, FileMode.Open, FileAccess.Write, FileShare.None);

        SymmetricAlgorithm alg = new AesManaged();
        alg.Mode = CipherMode.CBC;
        alg.Padding = PaddingMode.PKCS7;
        _readIV(alg, rawInput);
        alg.Key = _keyFromPassword(_getPassword(0));

        Stream cryptOutput = new CryptoStream(rawOutput, alg.CreateDecryptor(), CryptoStreamMode.Write);
        _pump(rawInput, cryptOutput);

        cryptOutput.Close();
        rawInput.Close();
        rawOutput.Close();
        File.Delete(filename);
        File.Move(tempfile, filename);
    }

    static byte[] _generateRandomSessionKey()
    {
        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        byte[] data = new byte[16];
        rng.GetBytes(data); // Fill buffer.
        return data;
    }

    static void _pump2(byte[] sessionKey, Stream output)
    {
        output.Write(sessionKey, 0, 16);
    }

    static void _encrypt2(string filename)
    {
        string tempfile = Path.GetTempFileName();
        FileStream rawInput = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
        FileStream rawOutput = new FileStream(tempfile, FileMode.Open, FileAccess.Write, FileShare.None);
        FileStream sessionKeyOutput = new FileStream(filename+"_sk", FileMode.OpenOrCreate, FileAccess.Write, FileShare.Write);

        //1. Generate a random session key (hint: RNGCryptoServiceProvider is your friend). 
        byte[] sessionKey = _generateRandomSessionKey();

        //2. Generate a CryptoStream based on the password.
        //   You'll use this to encrypt the session key (which is 16 bytes long if you choose a 128 bit session key). 
        //3. Set the encryption mode for this stream to ECB, since we don't require feedback when encrypting the session key.
        //   This just simplifies things so you don't need to record an initialization vector (IV) for your encrypted session key.
        //   Also, you can simplify things a bit by turning off padding for this CryptoStream,
        //   as long as the session key you're encrypting is an exact multiple of the block size you're using to encrypt it.
        //   For instance, a 128 bit key (16 bytes) doesn't need any padding if your algorithm is using an 8 or 16 byte block size. 
        SymmetricAlgorithm alg = new AesManaged();
        alg.Mode = CipherMode.ECB;
        alg.Padding = PaddingMode.None;
        alg.Key = _keyFromPassword(_getPassword(0));
        Stream cryptKey = new CryptoStream(sessionKeyOutput, alg.CreateEncryptor(), CryptoStreamMode.Write);

        //4. Pump the session key through the CryptoStream, thus encrypting it with the password and streaming it out to disk.
        //   Don't Close() this CryptoStream, just Flush() it. 
        _pump2(sessionKey, cryptKey);
        cryptKey.Flush();
        sessionKeyOutput.Close();

        //5. Create a second CryptoStream based on the session key, and use it to encrypt the file contents to disk.
        //   You'll want to use PKCS7 padding and the CBC cipher mode in this case, so you'll need to generate and record an IV. 
        SymmetricAlgorithm alg2 = new AesManaged();
        alg2.Mode = CipherMode.CBC;
        alg2.Padding = PaddingMode.PKCS7;
        alg2.GenerateIV();
        _writeIV(alg2, rawOutput);
        alg2.Key = sessionKey;
        Stream cryptOutput = new CryptoStream(rawOutput, alg2.CreateEncryptor(), CryptoStreamMode.Write);
        _pump(rawInput, cryptOutput);

        cryptOutput.Close();
        rawInput.Close();
        rawOutput.Close();
        File.Delete(filename);
        File.Move(tempfile, filename);
    }

    static byte[] _getKey(MemoryStream ms)
    {
        ms.Seek(0,SeekOrigin.Begin);
        byte[] b = new byte[16];
        int x = ms.Read(b,0,16);
        return b;
    }

    static void _decrypt2(string filename)
    {
        string tempfile = Path.GetTempFileName();
        FileStream rawInput = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
        FileStream rawOutput = new FileStream(tempfile, FileMode.Open, FileAccess.Write, FileShare.None);
        FileStream sessionKeyInput = new FileStream(filename+"_sk", FileMode.Open, FileAccess.Read, FileShare.Read);
        MemoryStream sessionKeyOuput = new MemoryStream(16);

        SymmetricAlgorithm alg = new AesManaged();
        alg.Mode = CipherMode.ECB;
        alg.Padding = PaddingMode.None;
        alg.Key = _keyFromPassword(_getPassword(0));

        Stream cryptKey = new CryptoStream(sessionKeyOuput, alg.CreateDecryptor(), CryptoStreamMode.Write);
        _pump(sessionKeyInput, cryptKey);
        cryptKey.Flush();
        sessionKeyInput.Close();
        byte[] sessionKey = _getKey(sessionKeyOuput);
        sessionKeyOuput.Close();

        SymmetricAlgorithm alg2 = new AesManaged();
        alg2.Mode = CipherMode.CBC;
        alg2.Padding = PaddingMode.PKCS7;
        _readIV(alg2, rawInput);
        alg2.Key = sessionKey;
        Stream cryptOutput = new CryptoStream(rawOutput, alg2.CreateDecryptor(), CryptoStreamMode.Write);
        _pump(rawInput, cryptOutput);

        cryptOutput.Close();
        rawInput.Close();
        rawOutput.Close();
        File.Delete(filename);
        File.Move(tempfile, filename);
        File.Delete(filename+"_sk");
    }

    static byte[] _keyFromPassword(string s)
    {
        // encode string into a byte array
        MemoryStream stringData = _stringToMemoryStream(s);

        // SHA creates a 20 byte hash
        byte[] shaHash = SHA1.Create().ComputeHash(stringData);

        // take the first 16 bytes for use as a 128 bit Rijndahl key
        byte[] key = new byte[16];
        Array.Copy(shaHash, 0, key, 0, key.Length);

        return key;
    }

    // given a password, estimate its strength in bits
    // note this assumes you've not chosen a password
    // that is easily guessed!!
    static int _passwordEntropy(string s)
    {
        // first determine the type of characters used
        bool usesUpperCaseAlpha = false;
        bool usesLowerCaseAlpha = false;
        bool usesNumerics = false;
        bool usesPunctuation = false;
        foreach (char c in s.ToCharArray())
        {
            if (char.IsLetter(c))
            {
                if (char.IsUpper(c))
                {
                    usesUpperCaseAlpha = true;
                }
                else usesLowerCaseAlpha = true;
            }
            else if (char.IsDigit(c))
            {
                usesNumerics = true;
            }
            else if (char.IsPunctuation(c))
            {
                usesPunctuation = true;
            }
            if (usesUpperCaseAlpha &&
            usesLowerCaseAlpha &&
            usesNumerics &&
            usesPunctuation)
            {
                break;
            }
        }
        int permutations = 0;
        if (usesUpperCaseAlpha) permutations += 26;
        if (usesLowerCaseAlpha) permutations += 26;
        if (usesNumerics) permutations += 10;
        if (usesPunctuation) permutations += 32;

        return Convert.ToInt32(Math.Log10(Math.Pow(permutations, s.Length)) / Math.Log10(2));
    }

    static int _estimateRequiredPasswordLength(int permutations, int requiredEntropy)
    {
        return Convert.ToInt32(Math.Log(Math.Pow(10, requiredEntropy * Math.Log10(2)), permutations));
    }

    static bool _verifyPasswordEntropy(string pwd, int requiredEntropy)
    {
        int pwdEntropy = _passwordEntropy(pwd);
        if (pwdEntropy >= requiredEntropy)
        {
            Console.WriteLine("your selected password has {0} bits of entropy - that'll work!", pwdEntropy);
            return true;
        }
        int est = _estimateRequiredPasswordLength(94, requiredEntropy);
        Console.WriteLine();
        Console.WriteLine("That password only has {0} bits of entropy.", pwdEntropy);
        Console.WriteLine("This program requires a password with {0} bits of entropy.", requiredEntropy);
        Console.WriteLine();
        Console.WriteLine("Use a mix of upper and lower case characters, numbers, and punctuation,");
        Console.WriteLine("and with a password of {0} characters you should be good", est);
        Console.WriteLine();
        return false;
    }

    static void _writeIV(SymmetricAlgorithm alg, Stream s)
    {
        BinaryWriter writer = new BinaryWriter(s);
        byte[] iv = alg.IV;
        writer.Write(iv.Length);
        writer.Write(iv, 0, iv.Length);
        writer.Flush();
    }

    static void _readIV(SymmetricAlgorithm alg, Stream s)
    {
        BinaryReader reader = new BinaryReader(s);
        int len = reader.ReadInt32();
        if (len > alg.BlockSize)
            throw new ApplicationException("Sanity check on IV length failed");
        byte[] iv = new Byte[len];
        if (len != reader.Read(iv, 0, len))
            throw new ApplicationException("Failed to read entire IV");
        alg.IV = iv;
    }

    static MemoryStream _stringToMemoryStream(string s)
    {
        // encode string into a byte array
        MemoryStream media = new MemoryStream();
        BinaryWriter writer = new BinaryWriter(media);
        writer.Write(s);
        writer.Flush();
        media.Seek(0, SeekOrigin.Begin);
        return media;
    }

    static void _pump(Stream input, Stream output)
    {
        byte[] buf = new byte[4096];
        int bytesRead;
        do
        {
            bytesRead = input.Read(buf, 0, buf.Length);
            if (0 != bytesRead)
                output.Write(buf, 0, bytesRead);
        } while (0 != bytesRead);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int GetStdHandle(int whichHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(int handle, out uint mode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(int handle, uint mode);

    const int STD_INPUT_HANDLE = -10;
    const uint ENABLE_ECHO_INPUT = 0x0004;

    // Pass the number of bits worth of entropy you desire.
    // This function will help the user pick a password
    // that meets your criteria. Pass 0 if you don't care
    // (for instance, if you're just asking for a decryption password)
    static string _getPassword(int requiredEntropy)
    {
        // turn off console echo
        int hConsole = GetStdHandle(STD_INPUT_HANDLE);
        uint oldMode;
        if (!GetConsoleMode(hConsole, out oldMode))
        {
            throw new COMException("GetConsoleMode failed", Marshal.GetLastWin32Error());
        }
        uint newMode = oldMode & ~ENABLE_ECHO_INPUT;
        if (!SetConsoleMode(hConsole, newMode))
        {
            throw new COMException("SetConsoleMode failed", Marshal.GetLastWin32Error());
        }
        string password;
        do
        {
            Console.Write("Enter password: ");
            password = Console.ReadLine();
            Console.WriteLine();
        } while (0 != requiredEntropy &&
        !_verifyPasswordEntropy(password, requiredEntropy));

        // restore console echo
        if (!SetConsoleMode(hConsole, oldMode))
        {
            throw new COMException("SetConsoleMode failed", Marshal.GetLastWin32Error());
        }
        return password;
    }
    static void _printUsage()
    {
        Console.WriteLine("to encrypt a file: fileEncryptor /encrypt filename");
        Console.WriteLine("to decrypt a file: fileEncryptor /decrypt filename");
    }
}
