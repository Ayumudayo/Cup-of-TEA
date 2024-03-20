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
            using (var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + process.Id))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    commandLine = obj["CommandLine"].ToString();
                    break;
                }
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
                throw ex;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                var decryptedCommand = Decrypt(File.ReadAllBytes(Path.ChangeExtension(Application.ExecutablePath, ".dat")));
                NativeMethods.WinExec(decryptedCommand, 5U);
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
            
            byte[] encryptedDataWithDpapi = ProtectedData.Protect(encryptedDataWithAes, null, DataProtectionScope.LocalMachine);

            return encryptedDataWithDpapi;
        }

        private byte[] EncryptWithAes(string data)
        {
            byte[] key = GetKey();
            byte[] iv;
            byte[] encryptedData;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.KeySize = 256;
                aesAlg.BlockSize = 128;

                // key의 역순에서 8바이트를 Salt로 사용
                using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, key.Reverse().Take(8).ToArray(), 1000))
                    aesAlg.Key = rfc2898DeriveBytes.GetBytes(aesAlg.KeySize / 8);

                // IV는 매 암호화 과정마다 변경됨
                aesAlg.GenerateIV();
                iv = aesAlg.IV;

                using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(data);
                        // StreamWriter를 닫지 않고, CryptoStream을 닫으면 데이터가 올바르게 Flush 되지 않을 수 있음
                        // SW를 이용해 CS에 데이터를 쓰면,
                        // 데이터는 암호화 되어 msEncrypt에 저장됨
                    }
                    // IV 다음에 암호화된 데이터 저장
                    // 16Byte(IV) + EncryptedData
                    encryptedData = iv.Concat(msEncrypt.ToArray()).ToArray();
                }
            }
            return encryptedData;
        }

        private string DecryptWithDpapiThenAes(byte[] encryptedData)
        {
            // Step 1: DPAPI를 사용하여 복호화
            byte[] decryptedDataWithDpapi;
            try
            {
                decryptedDataWithDpapi = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.LocalMachine);
            }
            catch (Exception ex)
            {
                throw new Exception("복호화 실패: " + ex.Message);
            }

            // Step 2: AES를 사용하여 복호화
            string decryptedText;
            try
            {
                decryptedText = DecryptWithAes(decryptedDataWithDpapi);
            }
            catch (Exception ex)
            {
                throw new Exception("복호화 실패: " + ex.Message);
            }

            return decryptedText;
        }

        private string DecryptWithAes(byte[] encryptedDataWithIv)
        {
            byte[] key = GetKey();
            byte[] iv = encryptedDataWithIv.Take(16).ToArray();
            byte[] encryptedData = encryptedDataWithIv.Skip(16).ToArray();

            string plaintext = null;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.KeySize = 256;
                aesAlg.BlockSize = 128;
                using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(key, key.Reverse().Take(8).ToArray(), 1000))
                    aesAlg.Key = rfc2898DeriveBytes.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = iv;
                
                // 같은 키와 IV로 복호화 진행
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    plaintext = srDecrypt.ReadToEnd();
                }
            }

            return plaintext;
        }

        private byte[] Encrypt(string data)
        {
            return EncryptWithAesThenDpapi(data);
        }

        private string Decrypt(byte[] data)
        {
            return DecryptWithDpapiThenAes(data);
        }

        private static class NativeMethods
        {
            [DllImport("kernel32.dll")]
            public static extern uint WinExec(string lpCmdLine, uint uCmdShow);
        }
    }
}
