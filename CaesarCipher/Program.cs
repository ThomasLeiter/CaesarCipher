using System;
using System.Text;

namespace CaesarCipher
{
    /// <summary>
    /// Abstract base class for the simple caesarean shift ciphers.
    /// </summary>
    abstract class CaesarCipher<KeyType>
    {
        public KeyType Key { protected get; set; }
        public string PlainAlphabet { get; set; }

        public CaesarCipher(KeyType key)
        {
            PlainAlphabet = "abcdefghijklmnopqrstuvwxyz";
            this.Key = key;
        }

        /// <summary>
        /// Encrypt a given text message and return the result.
        /// </summary> 
        public abstract string encipher(string text);

        /// <summary>
        /// Decrypt a given text message and return the result.
        /// </summary> 
        public abstract string decipher(string text);

        /// <summary>
        /// Helper method for shift ciphers to calculate 
        /// the positive remainder of a division independant
        /// of divident and divisor sign
        /// </summary>
        protected int Mod(int divident, int divisor)
        {
            return ((divident % divisor) + divisor) % divisor;
        }
    }

    /// <summary>
    /// Implementation of the simple shift cipher.
    /// </summary>
    class ShiftCipher : CaesarCipher<int>
    {

        public ShiftCipher(int key) : base(key) { }
        public override string decipher(string text)
        {
            // Use StringBuilder to avoid the creation of 
            // many new temporary strings and quadratic runtime
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < text.Length; ++i)
            {
                char textChar = text[i];
                int shiftIdx = Mod(PlainAlphabet.IndexOf(textChar) - Key, PlainAlphabet.Length);
                char shiftChar = PlainAlphabet[shiftIdx];
                encrypted.Append(shiftChar);
            }
            return encrypted.ToString();
        }

        public override string encipher(string text)
        {
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < text.Length; ++i)
            {
                char textChar = text[i];
                int shiftIdx = Mod(PlainAlphabet.IndexOf(textChar) + Key, PlainAlphabet.Length);
                char shiftChar = PlainAlphabet[shiftIdx];
                encrypted.Append(shiftChar);
            }
            return encrypted.ToString();
        }
    }

    /// <summary>
    /// Implementation of the Vigenere cipher
    /// </summary>
    class VigenereCipher : CaesarCipher<string>
    {
        public VigenereCipher(string key) : base(key) { }

        public override string decipher(string text)
        {
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < text.Length; ++i)
            {
                char keyChar = Key[i % Key.Length];
                char textChar = text[i];
                int shiftIdx = Mod(PlainAlphabet.IndexOf(textChar) - PlainAlphabet.IndexOf(keyChar), PlainAlphabet.Length);
                char shiftChar = PlainAlphabet[shiftIdx];
                encrypted.Append(shiftChar);
            }
            return encrypted.ToString();
        }

        public override string encipher(string text)
        {
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < text.Length; ++i)
            {
                char keyChar = Key[i % Key.Length];
                char textChar = text[i];
                int plainIdx = (PlainAlphabet.IndexOf(textChar) + PlainAlphabet.IndexOf(keyChar)) % PlainAlphabet.Length;
                char plainChar = PlainAlphabet[plainIdx];
                encrypted.Append(plainChar);
            }
            return encrypted.ToString();
        }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            string message = "helloworld";
            string encrypted, decrypted, output;
            Console.WriteLine("Testing ShiftCipher:");
            ShiftCipher cipher = new ShiftCipher(3);
            encrypted = cipher.encipher(message);
            decrypted = cipher.decipher(encrypted);
            output = $"Message:   {message}\nEncrypted: {encrypted}\nDecrypted: {decrypted}\n";
            Console.WriteLine(output);

            Console.WriteLine("Testing VigenereCipher:");
            VigenereCipher vigenere = new VigenereCipher("password");
            encrypted = vigenere.encipher(message);
            decrypted = vigenere.decipher(encrypted);
            output = $"Message:   {message}\nEncrypted: {encrypted}\nDecrypted: {decrypted}\n";
            Console.WriteLine(output);

            Console.WriteLine("Slighly more complex testing of VigenereCipher:");
            vigenere.PlainAlphabet = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + ",;.:!?/-_<>()[]{}$%&" + "0123456789" + " \t\n";
            vigenere.Key = "<-Pa55W0rd->";
            message = "This is an encrypted message that 87% of people cannot read!";
            encrypted = vigenere.encipher(message);
            decrypted = vigenere.decipher(encrypted);
            output = $"Message:   {message}\nEncrypted: {encrypted}\nDecrypted: {decrypted}\n";
            Console.WriteLine(output);

            // Prevent cmd from instantly closing
            Console.ReadLine();
        }
    }
}
