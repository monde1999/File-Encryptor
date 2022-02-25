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
                _encrypt(args[1]);
                break;
            case "/decrypt":
                _decrypt(args[1]);
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

        SymmetricAlgorithm alg = new RijndaelManaged();
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

        SymmetricAlgorithm alg = new RijndaelManaged();
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
