using SPHERE.Blockchain;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SPHERE.Configure
{
    public class BootstrapManifestFile
    {
        [JsonPropertyName("PublicKey")]
        private string PublicKey;
        [JsonPropertyName("IP")]
        private string IP;
        [JsonPropertyName("Port")]
        private string Port;

        public BootstrapManifestFile(string publicKey, string ip, string port)
        {
            PublicKey = publicKey;
            IP = ip;
            Port = port;
            
        }

        // Create a JSON file with ECC key and QR code reference
        public void GenerateKeyFile(Node node, string fileLocation)
        {
          var BootStrapManifest = new BootstrapManifestFile(Convert.ToBase64String(node.Peer.PublicEncryptKey), node.Peer.NodeIP, node.Peer.NodePort.ToString());

            if (string.IsNullOrWhiteSpace(fileLocation))
            {
                throw new ArgumentException("File location cannot be null or empty.", nameof(fileLocation));
            }

            string FilePath = Path.Combine(fileLocation, "public_key_qr.png");

            // Ensure the directory exists
            if (!Directory.Exists(FilePath))
            {
                Directory.CreateDirectory(FilePath);  // Create the directory if it doesn't exist
            }



            string jsonString = JsonSerializer.Serialize(BootStrapManifest, new JsonSerializerOptions { WriteIndented = true });

            File.WriteAllText("ecc_public_key.json", jsonString);

            Console.WriteLine("Key file generated: ecc_public_key.json");
        }

        // Method to import the manifest from a file (Optional)
        public static (string PublicKey, string IP, string Port) ImportManifest(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("Manifest file not found", filePath);
            }

            string jsonString = File.ReadAllText(filePath);
            var manifestData = JsonSerializer.Deserialize<dynamic>(jsonString);

            // Return the values as a tuple
            return (manifestData.PublicKey, manifestData.IP, manifestData.Port);
        }

        internal class QRCode
    {
        private int[,] qrMatrix;
        private int size;

        public QRCode(string data)
        {
            size = 21; // Version 1 QR Code
            qrMatrix = new int[size, size];

            AddFinderPatterns();
            AddTimingPatterns();
            AddFormatInformation();

            string binaryData = ConvertToBinary(data);
            PlaceData(binaryData);
        }



        private string ConvertToBinary(string data)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(data);
            string binaryString = string.Empty;

            foreach (var b in bytes)
            {
                binaryString += Convert.ToString(b, 2).PadLeft(8, '0');
            }

            return binaryString;
        }

        public Bitmap RenderQRCode(int pixelSize = 10)
        {
            Bitmap qrCodeImage = new Bitmap(size * pixelSize, size * pixelSize);

            using (Graphics g = Graphics.FromImage(qrCodeImage))
            {
                g.Clear(Color.White); // Background

                for (int row = 0; row < size; row++)
                {
                    for (int col = 0; col < size; col++)
                    {
                        if (qrMatrix[row, col] == 1)
                        {
                            g.FillRectangle(Brushes.Black, col * pixelSize, row * pixelSize, pixelSize, pixelSize);
                        }
                    }
                }
            }

            return qrCodeImage;
        }

        // Save the QR Code as an image (corrected version)
        internal string SaveQRCode(string fileLocation)
        {
            if (string.IsNullOrWhiteSpace(fileLocation))
            {
                throw new ArgumentException("File location cannot be null or empty.", nameof(fileLocation));
            }

            // Ensure the directory exists
            if (!Directory.Exists(fileLocation))
            {
                Directory.CreateDirectory(fileLocation);  // Create the directory if it doesn't exist
            }

            // Construct the full file path with proper handling of backslashes
            string qrFilePath = Path.Combine(fileLocation, "public_key_qr.png");

            // Generate and save the QR code image
            Bitmap qrCodeImage = RenderQRCode();
            qrCodeImage.Save(qrFilePath, ImageFormat.Png);

            return qrFilePath;
        }

        private void AddFinderPatterns()
        {
            DrawFinderSquare(0, 0); // Top-left
            DrawFinderSquare(0, size - 7); // Top-right
            DrawFinderSquare(size - 7, 0); // Bottom-left
        }

        private void DrawFinderSquare(int row, int col)
        {
            for (int r = 0; r < 7; r++)
            {
                for (int c = 0; c < 7; c++)
                {
                    // Draw square border
                    if (r == 0 || r == 6 || c == 0 || c == 6)
                        qrMatrix[row + r, col + c] = 1; // Black
                                                        // Inner square
                    else if (r >= 2 && r <= 4 && c >= 2 && c <= 4)
                        qrMatrix[row + r, col + c] = 1; // Black
                    else
                        qrMatrix[row + r, col + c] = 0; // White
                }
            }
        }

        private void AddTimingPatterns()
        {
            for (int i = 8; i < size - 8; i++)
            {
                int color = i % 2; // Alternating pattern
                qrMatrix[6, i] = color;
                qrMatrix[i, 6] = color;
            }
        }

        private void AddFormatInformation()
        {
            string formatBits = "111011111000100"; // Example for Error Correction L and Mask 0

            // Reserve and fill Top-left format information
            for (int i = 0; i < 9; i++)
            {
                int bit = i < formatBits.Length ? (formatBits[i] == '1' ? 1 : 0) : 0;

                // Horizontal (row 8)
                qrMatrix[8, i] = bit;

                // Vertical (column 8)
                qrMatrix[i, 8] = bit;
            }

            // Reserve and fill Top-right format information
            for (int i = 0; i < 8; i++)
            {
                int bit = i < formatBits.Length ? (formatBits[i] == '1' ? 1 : 0) : 0;
                qrMatrix[i, size - 8] = bit; // Reserved column
            }

            // Reserve and fill Bottom-left format information
            for (int i = 0; i < 8; i++)
            {
                int bit = i < formatBits.Length ? (formatBits[i] == '1' ? 1 : 0) : 0;
                qrMatrix[size - 8, i] = bit; // Reserved row
            }
        }


        private void PlaceData(string binaryData)
        {
            int dataIndex = 0;
            bool goingUp = true;

            for (int col = size - 1; col > 0; col -= 2)
            {
                if (col == 6) col--; // Skip the vertical timing pattern column

                for (int row = 0; row < size; row++)
                {
                    int currentRow = goingUp ? size - 1 - row : row;

                    for (int i = 0; i < 2; i++) // Two columns at a time
                    {
                        if (qrMatrix[currentRow, col - i] == 0)
                        {
                            if (dataIndex < binaryData.Length)
                            {
                                qrMatrix[currentRow, col - i] = binaryData[dataIndex] == '1' ? 1 : 0;
                                dataIndex++;
                            }
                            else
                            {
                                qrMatrix[currentRow, col - i] = 0; // Padding if data ends
                            }
                        }
                    }
                }

                goingUp = !goingUp; // Switch direction
            }
        }

    }
    }

}
