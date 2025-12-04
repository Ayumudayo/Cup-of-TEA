using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CupofTEA
{
    public partial class MainWindow : Form
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void MainWindow_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            Process process = null;
            try
            {
                process = Process.GetProcessesByName("ffxiv_dx11").FirstOrDefault();
                if (process == null) throw new Exception();
            }
            catch
            {
                MessageBox.Show("ffxiv_dx11.exe가 실행중이 아닙니다.");
                return;
            }

            // 쿼리로 명령줄을 가져온다
            var commandLine = "";
            try
            {
                var query = $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}";
                using (var searcher = new ManagementObjectSearcher("root\\CIMV2", query))
                using (var objects = searcher.Get())
                {
                    foreach (var obj in objects)
                    {
                        commandLine = obj["CommandLine"]?.ToString() ?? string.Empty;
                        break;
                    }
                }
            }
            catch (ManagementException ex)
            {
                MessageBox.Show($"WMI 오류: {ex.Message}\n오류 코드: {ex.ErrorCode}\n상세 정보: {ex.ErrorInformation}");
                throw;
            }

            try
            {
                var encryptedData = Encrypt(commandLine);
                File.WriteAllBytes(Path.ChangeExtension(Application.ExecutablePath, ".dat"), encryptedData);
                MessageBox.Show("나는 알렉산더... 기계장치 신...");
            }
            catch (Exception ex)
            {
                MessageBox.Show("암호화 실패!!!");
                throw;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                var decryptedCommand = Decrypt(File.ReadAllBytes(Path.ChangeExtension(Application.ExecutablePath, ".dat")));
                Process.Start(new ProcessStartInfo(decryptedCommand) { UseShellExecute = true });
                Application.Exit();
            }
            catch
            {
                // Handle exceptions or ignore
            }
        }

        private void AddHardwareInfo(StringBuilder sb, string wmiClass, string propertyName)
        {
            using (var searcher = new ManagementObjectSearcher($"SELECT {propertyName} FROM {wmiClass}"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    sb.AppendFormat("{0}: {1}\n", propertyName, obj[propertyName]);
                }
            }
        }

        private byte[] GetKey()
        {
            var sb = new StringBuilder();
            using (var searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Processor"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    sb.AppendFormat("Architecture : {0}\n", obj["Architecture"]);
                    sb.AppendFormat("Caption      : {0}\n", obj["Caption"]);
                    sb.AppendFormat("Family       : {0}\n", obj["Family"]);
                    sb.AppendFormat("ProcessorId  : {0}\n", obj["ProcessorId"]);
                }
            }

            AddHardwareInfo(sb, "Win32_BaseBoard", "SerialNumber");
            AddHardwareInfo(sb, "Win32_BIOS", "SerialNumber");

            return Encoding.ASCII.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(sb.ToString())));
        }

        public byte[] EncryptWithAesThenDpapi(string data)
        {
            byte[] encryptedDataWithAes = EncryptWithAes(data);
            try
            {
                return ProtectedData.Protect(encryptedDataWithAes, null, DataProtectionScope.CurrentUser);
            }
            finally
            {
                Array.Clear(encryptedDataWithAes, 0, encryptedDataWithAes.Length);
            }
        }

        private byte[] EncryptWithAes(string data)
        {
            byte[] key = GetKey();
            byte[] salt = new byte[16];
            byte[] aesKey = new byte[32]; // AES-256
            byte[] nonce = new byte[12]; // GCM standard nonce size
            byte[] tag = new byte[16]; // GCM standard tag size
            byte[] ciphertext = null;
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(data);

            try
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                    rng.GetBytes(nonce);
                }

                using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, salt, 100000, HashAlgorithmName.SHA256))
                {
                    byte[] derivedKey = rfc2898DeriveBytes.GetBytes(32);
                    Array.Copy(derivedKey, aesKey, 32);
                    Array.Clear(derivedKey, 0, derivedKey.Length);
                }

                ciphertext = new byte[plaintextBytes.Length];

                using (var aesGcm = new AesGcm(aesKey, 16)) // 16 bytes tag size
                {
                    aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
                }

                // Structure: Salt(16) + Nonce(12) + Tag(16) + Ciphertext
                byte[] result = new byte[salt.Length + nonce.Length + tag.Length + ciphertext.Length];
                Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
                Buffer.BlockCopy(tag, 0, result, salt.Length + nonce.Length, tag.Length);
                Buffer.BlockCopy(ciphertext, 0, result, salt.Length + nonce.Length + tag.Length, ciphertext.Length);

                return result;
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                Array.Clear(aesKey, 0, aesKey.Length);
                Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
                // salt, nonce, tag, ciphertext are public or encrypted, but good practice to clear if reused, though here they are local.
                // We don't clear salt/nonce/tag/ciphertext immediately as they are part of the result, but intermediate aesKey and plaintext MUST be cleared.
            }
        }

        private string DecryptWithDpapiThenAes(byte[] encryptedData)
        {
            // Step 1: DPAPI를 사용하여 복호화
            byte[] decryptedDataWithDpapi = null;
            try
            {
                decryptedDataWithDpapi = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
                // Step 2: AES를 사용하여 복호화
                return DecryptWithAes(decryptedDataWithDpapi);
            }
            catch (Exception ex)
            {
                throw new Exception("복호화 실패: " + ex.Message);
            }
            finally
            {
                if (decryptedDataWithDpapi != null)
                {
                    Array.Clear(decryptedDataWithDpapi, 0, decryptedDataWithDpapi.Length);
                }
            }
        }

        private string DecryptWithAes(byte[] encryptedDataWithMeta)
        {
            if (encryptedDataWithMeta.Length < 16 + 12 + 16)
                throw new ArgumentException("Invalid encrypted data format");

            byte[] key = GetKey();
            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[encryptedDataWithMeta.Length - 16 - 12 - 16];
            byte[] aesKey = new byte[32];
            byte[] plaintextBytes = new byte[ciphertext.Length];

            try
            {
                Buffer.BlockCopy(encryptedDataWithMeta, 0, salt, 0, 16);
                Buffer.BlockCopy(encryptedDataWithMeta, 16, nonce, 0, 12);
                Buffer.BlockCopy(encryptedDataWithMeta, 16 + 12, tag, 0, 16);
                Buffer.BlockCopy(encryptedDataWithMeta, 16 + 12 + 16, ciphertext, 0, ciphertext.Length);

                using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, salt, 100000, HashAlgorithmName.SHA256))
                {
                    byte[] derivedKey = rfc2898DeriveBytes.GetBytes(32);
                    Array.Copy(derivedKey, aesKey, 32);
                    Array.Clear(derivedKey, 0, derivedKey.Length);
                }

                using (var aesGcm = new AesGcm(aesKey, 16))
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, plaintextBytes);
                }

                return Encoding.UTF8.GetString(plaintextBytes);
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                Array.Clear(aesKey, 0, aesKey.Length);
                Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
            }
        }

        private byte[] Encrypt(string data)
        {
            return EncryptWithAesThenDpapi(data);
        }

        private string Decrypt(byte[] data)
        {
            return DecryptWithDpapiThenAes(data);
        }
    }
}
