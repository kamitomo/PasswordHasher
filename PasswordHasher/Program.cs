using System;

namespace PasswordHasher
{
    class Program
    {
        static void Main(string[] args)
        {
            PasswordHasher hasher = new PasswordHasher();

            (string hashedPassword, byte[] salt) = hasher.HashPassword("password");

            Message(hasher.VerifyPassword(hashedPassword, "foobar", salt));
            Message(hasher.VerifyPassword(hashedPassword, "hogehoge", salt));
            Message(hasher.VerifyPassword(hashedPassword, "password", salt));
        }

        static void Message(bool verified)
        {
            if (verified)
            {
                Console.WriteLine("パスワードを確認できた");
            }
            else
            {
                Console.WriteLine("パスワードを確認できなかった");
            }
        }
    }
}
