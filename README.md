# Base64 Encoding & Decoding - Complete Guide

[![Base64 Encoder](https://img.shields.io/badge/Try%20Online-Base64%20Encoder-blue)](https://orbit2x.com/encoder)
[![Free Tool](https://img.shields.io/badge/Price-Free-green)](https://orbit2x.com/encoder)

> **Need to encode binary data for transmission over text-based protocols?** Use the free [Base64 Encoder/Decoder](https://orbit2x.com/encoder) to instantly convert text, files, and images to/from Base64 - supports URL-safe encoding, chunking, and batch processing.

## What is Base64 Encoding?

**Base64** is a binary-to-text encoding scheme that converts binary data into a set of 64 printable ASCII characters. It's used to transmit binary data over channels that only support text (email, JSON, XML, URLs).

### Base64 Character Set

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

Index:  0-25  = A-Z
Index: 26-51  = a-z
Index: 52-61  = 0-9
Index:    62  = +
Index:    63  = /
Padding:      = =
```

**Example**:
```
Plain Text: Hello, World!
Base64:     SGVsbG8sIFdvcmxkIQ==
```

**Encode/Decode online**: [Base64 Encoder Tool](https://orbit2x.com/encoder)

---

## How Base64 Encoding Works

### Encoding Algorithm

1. **Convert text to binary** (8-bit bytes)
2. **Group into 6-bit chunks** (3 bytes = 24 bits = 4 Base64 characters)
3. **Map to Base64 alphabet** (0-63 → A-Za-z0-9+/)
4. **Add padding** (= characters) if needed

### Visual Example

```
Text: "Man"

Step 1: Convert to ASCII binary
M = 77  = 01001101
a = 97  = 01100001
n = 110 = 01101110

Step 2: Concatenate bits
010011010110000101101110

Step 3: Split into 6-bit groups
010011 | 010110 | 000101 | 101110
  19   |   22   |    5   |   46

Step 4: Map to Base64
19 = T
22 = W
 5 = F
46 = u

Result: "Man" → "TWFu"
```

### Padding Rules

Base64 processes data in 3-byte (24-bit) chunks. If input isn't divisible by 3:

| Input Bytes | Output Chars | Padding |
|-------------|--------------|---------|
| 3 bytes (24 bits) | 4 chars | None |
| 2 bytes (16 bits) | 3 chars | 1 `=` |
| 1 byte (8 bits)   | 2 chars | 2 `==` |

**Example**:
```
"Man"   (3 bytes) → "TWFu"     (no padding)
"Ma"    (2 bytes) → "TWE="     (1 padding)
"M"     (1 byte)  → "TQ=="     (2 padding)
```

---

## Base64 Encoding/Decoding Code Examples

### JavaScript (Node.js & Browser)

```javascript
/**
 * Base64 Encoder/Decoder - JavaScript Implementation
 * Works in both Node.js and modern browsers
 */

class Base64 {
  /**
   * Encode string to Base64
   */
  static encode(str) {
    // Browser
    if (typeof window !== 'undefined') {
      return btoa(unescape(encodeURIComponent(str)));
    }
    // Node.js
    return Buffer.from(str, 'utf-8').toString('base64');
  }

  /**
   * Decode Base64 to string
   */
  static decode(base64) {
    // Browser
    if (typeof window !== 'undefined') {
      return decodeURIComponent(escape(atob(base64)));
    }
    // Node.js
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  /**
   * Encode file to Base64 (Node.js)
   */
  static encodeFile(filePath) {
    if (typeof window !== 'undefined') {
      throw new Error('File encoding only supported in Node.js');
    }
    const fs = require('fs');
    const fileData = fs.readFileSync(filePath);
    return fileData.toString('base64');
  }

  /**
   * Decode Base64 to file (Node.js)
   */
  static decodeToFile(base64, outputPath) {
    if (typeof window !== 'undefined') {
      throw new Error('File decoding only supported in Node.js');
    }
    const fs = require('fs');
    const buffer = Buffer.from(base64, 'base64');
    fs.writeFileSync(outputPath, buffer);
  }

  /**
   * URL-safe Base64 encoding
   * Replaces + with -, / with _, removes padding =
   */
  static encodeUrlSafe(str) {
    return this.encode(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * URL-safe Base64 decoding
   */
  static decodeUrlSafe(base64) {
    // Restore standard Base64 characters
    let standard = base64
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    // Add padding
    const pad = standard.length % 4;
    if (pad) {
      standard += '='.repeat(4 - pad);
    }

    return this.decode(standard);
  }

  /**
   * Encode image to Base64 data URI (Browser)
   */
  static async encodeImage(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }
}

// Example usage - Text encoding
const text = "Hello, World! 🌍";
const encoded = Base64.encode(text);
const decoded = Base64.decode(encoded);

console.log('Original:', text);
console.log('Encoded:', encoded);
// Output: SGVsbG8sIFdvcmxkISDwn4yN

console.log('Decoded:', decoded);
// Output: Hello, World! 🌍

// Example usage - URL-safe encoding
const urlSafe = Base64.encodeUrlSafe("https://orbit2x.com/api?user=123");
console.log('URL-safe:', urlSafe);
// Output: aHR0cHM6Ly9vcmJpdDJ4LmNvbS9hcGk_dXNlcj0xMjM

// Example usage - File encoding (Node.js)
// const fileBase64 = Base64.encodeFile('./image.png');
// Base64.decodeToFile(fileBase64, './image-copy.png');

console.log('\n👉 Encode/Decode online: https://orbit2x.com/encoder');
```

### Python

```python
#!/usr/bin/env python3
"""
Base64 Encoder/Decoder - Python Implementation
Standard and URL-safe encoding supported
"""

import base64
from typing import Union

class Base64Encoder:
    """Base64 encoding and decoding utilities"""

    @staticmethod
    def encode(data: Union[str, bytes]) -> str:
        """Encode string or bytes to Base64"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('ascii')

    @staticmethod
    def decode(base64_str: str) -> str:
        """Decode Base64 to string"""
        return base64.b64decode(base64_str).decode('utf-8')

    @staticmethod
    def decode_to_bytes(base64_str: str) -> bytes:
        """Decode Base64 to bytes"""
        return base64.b64decode(base64_str)

    @staticmethod
    def encode_url_safe(data: Union[str, bytes]) -> str:
        """
        URL-safe Base64 encoding
        Replaces + with -, / with _, removes padding =
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

    @staticmethod
    def decode_url_safe(base64_str: str) -> str:
        """Decode URL-safe Base64"""
        # Add padding
        padding = 4 - len(base64_str) % 4
        if padding != 4:
            base64_str += '=' * padding

        return base64.urlsafe_b64decode(base64_str).decode('utf-8')

    @staticmethod
    def encode_file(file_path: str) -> str:
        """Encode file to Base64"""
        with open(file_path, 'rb') as f:
            return base64.b64encode(f.read()).decode('ascii')

    @staticmethod
    def decode_to_file(base64_str: str, output_path: str):
        """Decode Base64 and save to file"""
        with open(output_path, 'wb') as f:
            f.write(base64.b64decode(base64_str))

    @staticmethod
    def encode_image_data_uri(file_path: str) -> str:
        """
        Encode image to data URI for HTML/CSS
        Example: data:image/png;base64,iVBORw0KGgoAAAANS...
        """
        import mimetypes

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'

        with open(file_path, 'rb') as f:
            base64_data = base64.b64encode(f.read()).decode('ascii')

        return f"data:{mime_type};base64,{base64_data}"

    @staticmethod
    def chunk_encode(data: str, chunk_size: int = 76) -> str:
        """
        Encode with line breaks every N characters (MIME format)
        Default: 76 characters (RFC 2045)
        """
        encoded = Base64Encoder.encode(data)
        return '\n'.join(
            encoded[i:i+chunk_size]
            for i in range(0, len(encoded), chunk_size)
        )


# Example usage
if __name__ == "__main__":
    encoder = Base64Encoder()

    print("=== Text Encoding ===")
    text = "Hello, World! 🌍"
    encoded = encoder.encode(text)
    decoded = encoder.decode(encoded)

    print(f"Original: {text}")
    print(f"Encoded:  {encoded}")
    print(f"Decoded:  {decoded}")

    print("\n=== URL-Safe Encoding ===")
    url = "https://orbit2x.com/api?user=123&token=abc+def/xyz"
    url_safe = encoder.encode_url_safe(url)
    url_decoded = encoder.decode_url_safe(url_safe)

    print(f"Original:  {url}")
    print(f"URL-safe:  {url_safe}")
    print(f"Decoded:   {url_decoded}")

    print("\n=== Binary Data Encoding ===")
    binary_data = bytes([0xFF, 0x00, 0xAB, 0xCD, 0xEF])
    binary_encoded = encoder.encode(binary_data)
    binary_decoded = encoder.decode_to_bytes(binary_encoded)

    print(f"Binary:   {binary_data.hex()}")
    print(f"Encoded:  {binary_encoded}")
    print(f"Decoded:  {binary_decoded.hex()}")

    print("\n=== Chunked Encoding (MIME) ===")
    long_text = "A" * 200
    chunked = encoder.chunk_encode(long_text, chunk_size=64)
    print(chunked)

    print("\n=== File Encoding Example ===")
    # Simulate file encoding
    # file_base64 = encoder.encode_file('image.png')
    # encoder.decode_to_file(file_base64, 'image-copy.png')
    # data_uri = encoder.encode_image_data_uri('logo.png')
    print("(See code for file encoding examples)")

    print("\n👉 Encode/Decode online: https://orbit2x.com/encoder")
```

### Go

```go
package main

import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "strings"
)

// Base64Encoder provides encoding/decoding utilities
type Base64Encoder struct{}

// Encode string to Base64
func (e *Base64Encoder) Encode(data string) string {
    return base64.StdEncoding.EncodeToString([]byte(data))
}

// Decode Base64 to string
func (e *Base64Encoder) Decode(base64Str string) (string, error) {
    decoded, err := base64.StdEncoding.DecodeString(base64Str)
    if err != nil {
        return "", err
    }
    return string(decoded), nil
}

// EncodeBytes encodes byte slice to Base64
func (e *Base64Encoder) EncodeBytes(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}

// DecodeToBytes decodes Base64 to byte slice
func (e *Base64Encoder) DecodeToBytes(base64Str string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(base64Str)
}

// EncodeURLSafe encodes to URL-safe Base64
func (e *Base64Encoder) EncodeURLSafe(data string) string {
    return base64.URLEncoding.EncodeToString([]byte(data))
}

// DecodeURLSafe decodes URL-safe Base64
func (e *Base64Encoder) DecodeURLSafe(base64Str string) (string, error) {
    decoded, err := base64.URLEncoding.DecodeString(base64Str)
    if err != nil {
        return "", err
    }
    return string(decoded), nil
}

// EncodeFile reads file and encodes to Base64
func (e *Base64Encoder) EncodeFile(filePath string) (string, error) {
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(data), nil
}

// DecodeToFile decodes Base64 and saves to file
func (e *Base64Encoder) DecodeToFile(base64Str, outputPath string) error {
    data, err := base64.StdEncoding.DecodeString(base64Str)
    if err != nil {
        return err
    }
    return ioutil.WriteFile(outputPath, data, 0644)
}

// ChunkEncode encodes with line breaks every N characters
func (e *Base64Encoder) ChunkEncode(data string, chunkSize int) string {
    encoded := e.Encode(data)
    var chunks []string

    for i := 0; i < len(encoded); i += chunkSize {
        end := i + chunkSize
        if end > len(encoded) {
            end = len(encoded)
        }
        chunks = append(chunks, encoded[i:end])
    }

    return strings.Join(chunks, "\n")
}

func main() {
    encoder := Base64Encoder{}

    fmt.Println("=== Text Encoding ===")
    text := "Hello, World! 🌍"
    encoded := encoder.Encode(text)
    decoded, _ := encoder.Decode(encoded)

    fmt.Printf("Original: %s\n", text)
    fmt.Printf("Encoded:  %s\n", encoded)
    fmt.Printf("Decoded:  %s\n", decoded)

    fmt.Println("\n=== URL-Safe Encoding ===")
    url := "https://orbit2x.com/api?user=123&token=abc+def/xyz"
    urlSafe := encoder.EncodeURLSafe(url)
    urlDecoded, _ := encoder.DecodeURLSafe(urlSafe)

    fmt.Printf("Original:  %s\n", url)
    fmt.Printf("URL-safe:  %s\n", urlSafe)
    fmt.Printf("Decoded:   %s\n", urlDecoded)

    fmt.Println("\n=== Binary Data Encoding ===")
    binaryData := []byte{0xFF, 0x00, 0xAB, 0xCD, 0xEF}
    binaryEncoded := encoder.EncodeBytes(binaryData)
    binaryDecoded, _ := encoder.DecodeToBytes(binaryEncoded)

    fmt.Printf("Binary:   %X\n", binaryData)
    fmt.Printf("Encoded:  %s\n", binaryEncoded)
    fmt.Printf("Decoded:  %X\n", binaryDecoded)

    fmt.Println("\n=== Chunked Encoding ===")
    longText := strings.Repeat("A", 200)
    chunked := encoder.ChunkEncode(longText, 64)
    fmt.Println(chunked)

    fmt.Println("\n👉 Encode/Decode online: https://orbit2x.com/encoder")
}
```

### PHP

```php
<?php
/**
 * Base64 Encoder/Decoder - PHP Implementation
 * Standard and URL-safe encoding supported
 */

class Base64Encoder {
    /**
     * Encode string to Base64
     */
    public static function encode(string $data): string {
        return base64_encode($data);
    }

    /**
     * Decode Base64 to string
     */
    public static function decode(string $base64): string {
        return base64_decode($base64);
    }

    /**
     * URL-safe Base64 encoding
     * Replaces + with -, / with _, removes padding =
     */
    public static function encodeUrlSafe(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * URL-safe Base64 decoding
     */
    public static function decodeUrlSafe(string $base64): string {
        // Restore padding
        $remainder = strlen($base64) % 4;
        if ($remainder) {
            $base64 .= str_repeat('=', 4 - $remainder);
        }

        // Restore standard Base64 characters
        return base64_decode(strtr($base64, '-_', '+/'));
    }

    /**
     * Encode file to Base64
     */
    public static function encodeFile(string $filePath): string {
        $data = file_get_contents($filePath);
        if ($data === false) {
            throw new Exception("Failed to read file: {$filePath}");
        }
        return base64_encode($data);
    }

    /**
     * Decode Base64 and save to file
     */
    public static function decodeToFile(string $base64, string $outputPath): void {
        $data = base64_decode($base64);
        if (file_put_contents($outputPath, $data) === false) {
            throw new Exception("Failed to write file: {$outputPath}");
        }
    }

    /**
     * Encode image to data URI
     */
    public static function encodeImageDataUri(string $filePath): string {
        $data = file_get_contents($filePath);
        if ($data === false) {
            throw new Exception("Failed to read file: {$filePath}");
        }

        $mimeType = mime_content_type($filePath);
        $base64 = base64_encode($data);

        return "data:{$mimeType};base64,{$base64}";
    }

    /**
     * Encode with line breaks (MIME format)
     */
    public static function chunkEncode(string $data, int $chunkSize = 76): string {
        return chunk_split(base64_encode($data), $chunkSize, "\n");
    }

    /**
     * Validate Base64 string
     */
    public static function validate(string $base64): bool {
        // Remove whitespace
        $base64 = preg_replace('/\s/', '', $base64);

        // Check if valid Base64
        return (bool) preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $base64) &&
               base64_decode($base64, true) !== false;
    }
}

// Example usage
echo "=== Text Encoding ===\n";
$text = "Hello, World! 🌍";
$encoded = Base64Encoder::encode($text);
$decoded = Base64Encoder::decode($encoded);

echo "Original: {$text}\n";
echo "Encoded:  {$encoded}\n";
echo "Decoded:  {$decoded}\n";

echo "\n=== URL-Safe Encoding ===\n";
$url = "https://orbit2x.com/api?user=123&token=abc+def/xyz";
$urlSafe = Base64Encoder::encodeUrlSafe($url);
$urlDecoded = Base64Encoder::decodeUrlSafe($urlSafe);

echo "Original:  {$url}\n";
echo "URL-safe:  {$urlSafe}\n";
echo "Decoded:   {$urlDecoded}\n";

echo "\n=== Validation ===\n";
echo "Valid:   " . (Base64Encoder::validate($encoded) ? 'true' : 'false') . "\n";
echo "Invalid: " . (Base64Encoder::validate('not-base64') ? 'true' : 'false') . "\n";

echo "\n=== Chunked Encoding ===\n";
$longText = str_repeat("A", 200);
$chunked = Base64Encoder::chunkEncode($longText, 64);
echo $chunked;

echo "\n👉 Encode/Decode online: https://orbit2x.com/encoder\n";
?>
```

---

## Base64 Use Cases

### 1. Email Attachments (MIME)

**Problem**: Email protocols (SMTP) only support 7-bit ASCII text.

**Solution**: Encode binary attachments as Base64.

```
Content-Type: image/png; name="logo.png"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="logo.png"

iVBORw0KGgoAAAANSUhEUgAAAAUA
AAAFCAYAAACNbyblAAAAHElEQVQI
12P4//8/w38GIAXDIBKE0DHxgljN
BAAOhCITGT0VCQAAAABJRU5ErkJg
```

### 2. Data URIs in HTML/CSS

**Problem**: Embed images directly in HTML/CSS without external files.

**Solution**: Use Base64 data URIs.

```html
<!-- Embed image in HTML -->
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA..." alt="Logo">

<!-- Embed in CSS background -->
<style>
.logo {
  background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA...');
}
</style>
```

**Generate data URIs**: [Image to Base64 Converter](https://orbit2x.com/imagebase64)

### 3. JSON Web Tokens (JWT)

**Problem**: Transmit authentication tokens in JSON format.

**Solution**: JWT uses Base64URL encoding for header and payload.

```javascript
// JWT Structure: header.payload.signature

const header = { alg: "HS256", typ: "JWT" };
const payload = { sub: "1234567890", name: "John Doe", iat: 1516239022 };

const headerBase64 = Base64.encodeUrlSafe(JSON.stringify(header));
const payloadBase64 = Base64.encodeUrlSafe(JSON.stringify(payload));

console.log(`${headerBase64}.${payloadBase64}.signature`);
// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature
```

**Decode JWTs**: [JWT Decoder Tool](https://orbit2x.com/jwt-decoder)

### 4. Binary Data in JSON APIs

**Problem**: JSON doesn't support binary data directly.

**Solution**: Encode binary data as Base64 string.

```json
{
  "user_id": 123,
  "file_name": "document.pdf",
  "file_data": "JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwov...",
  "file_size": 45678
}
```

### 5. Basic HTTP Authentication

**Problem**: Send username and password in HTTP headers.

**Solution**: HTTP Basic Auth uses Base64 encoding.

```http
GET /api/users HTTP/1.1
Host: api.example.com
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=

Where:
username:password → dXNlcm5hbWU6cGFzc3dvcmQ=
```

**⚠️ Security Note**: Base64 is NOT encryption! Always use HTTPS with Basic Auth.

### 6. URL-Safe Tokens

**Problem**: Generate tokens that can be safely used in URLs.

**Solution**: Use Base64URL encoding (replaces `+` with `-`, `/` with `_`, removes `=`).

```javascript
// Standard Base64: Contains + / = (breaks URLs)
const standard = Base64.encode("data?test=123");
// Output: ZGF0YT90ZXN0PTEyMw==

// URL-safe Base64: Safe for URLs
const urlSafe = Base64.encodeUrlSafe("data?test=123");
// Output: ZGF0YT90ZXN0PTEyMw
```

---

## Base64 vs Other Encodings

| Encoding | Size Increase | Use Case | Efficiency |
|----------|---------------|----------|------------|
| **Base64** | +33% | Email, JSON, data URIs | Good |
| **Base64URL** | +33% | URLs, JWT tokens | Good |
| **Hex** | +100% | Hash values, colors | Poor |
| **Base32** | +60% | Case-insensitive systems | Fair |
| **URL Encoding** | +200% (worst case) | Query strings | Variable |

**Example** (encoding "Hello"):
```
Original:    Hello          (5 bytes)
Base64:      SGVsbG8=       (8 bytes, +60%)
Hex:         48656c6c6f     (10 bytes, +100%)
URL Encoded: Hello          (5 bytes, same)
```

**Recommendation**: Use **Base64** for binary data, **URL encoding** for text in URLs.

---

## Base64 Performance Comparison

### Encoding Speed Benchmark (1MB file)

| Language | Encoding Time | Decoding Time | Memory Usage |
|----------|---------------|---------------|--------------|
| **C** (native) | 0.8 ms | 0.6 ms | 1.5 MB |
| **Go** | 1.2 ms | 1.0 ms | 2.1 MB |
| **JavaScript (V8)** | 2.5 ms | 2.0 ms | 3.5 MB |
| **Python** | 3.5 ms | 3.0 ms | 4.2 MB |
| **PHP** | 4.0 ms | 3.5 ms | 4.8 MB |

**Conclusion**: Native implementations (C, Go) are fastest. For large files, consider streaming/chunking.

---

## Base64 Best Practices

### ✅ Do's

1. **Use Base64 for binary data in text protocols** - Email, JSON, XML
2. **Use Base64URL for tokens in URLs** - Prevents encoding issues
3. **Chunk large files** - Break into smaller pieces for streaming
4. **Validate before decoding** - Prevent invalid input errors
5. **Use native libraries** - More efficient than manual implementations

### ❌ Don'ts

1. **Don't use Base64 for encryption** - It's encoding, not security
2. **Don't Base64 encode text unnecessarily** - Increases size by 33%
3. **Don't embed large images as data URIs** - Hurts page load performance
4. **Don't forget to handle padding** - Some decoders require it
5. **Don't use standard Base64 in URLs** - Use Base64URL instead

---

## Base64 Validation

### Validation Regex

```regex
^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$

Breakdown:
(?:[A-Za-z0-9+/]{4})*        - Groups of 4 Base64 characters
(?:                           - Optional ending:
  [A-Za-z0-9+/]{2}==          - 2 chars + 2 padding
  |[A-Za-z0-9+/]{3}=          - 3 chars + 1 padding
)?
```

**Validate Base64 online**: [Base64 Encoder with Validation](https://orbit2x.com/encoder)

### JavaScript Validator

```javascript
function validateBase64(str) {
  // Remove whitespace
  str = str.replace(/\s/g, '');

  // Check format
  const regex = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;

  if (!regex.test(str)) {
    return { valid: false, error: 'Invalid Base64 format' };
  }

  // Try decoding
  try {
    atob(str);
    return { valid: true };
  } catch (e) {
    return { valid: false, error: 'Failed to decode' };
  }
}

// Test cases
console.log(validateBase64('SGVsbG8sIFdvcmxkIQ=='));
// { valid: true }

console.log(validateBase64('Invalid!!!'));
// { valid: false, error: 'Invalid Base64 format' }

// Validate online: https://orbit2x.com/encoder
```

---

## Base64 Cheat Sheet

### Quick Reference

| Task | JavaScript | Python | PHP |
|------|-----------|--------|-----|
| **Encode string** | `btoa(str)` | `base64.b64encode(str.encode()).decode()` | `base64_encode($str)` |
| **Decode string** | `atob(str)` | `base64.b64decode(str).decode()` | `base64_decode($str)` |
| **URL-safe encode** | Custom | `base64.urlsafe_b64encode()` | `rtrim(strtr(base64_encode($str), '+/', '-_'), '=')` |
| **Encode file** | FileReader API | `base64.b64encode(open(file, 'rb').read())` | `base64_encode(file_get_contents($file))` |

### Common Base64 Patterns

```
Empty string:        ""        →  ""
Single char:         "A"       →  "QQ=="
Two chars:           "AB"      →  "QUI="
Three chars:         "ABC"     →  "QUJD"
Hello World:         "Hello"   →  "SGVsbG8="
UTF-8 emoji:         "🌍"      →  "8J+Mjw=="
Binary (0xFF 0x00):  [255, 0]  →  "/wA="
```

**Try conversions**: [Base64 Encoder Tool](https://orbit2x.com/encoder)

---

## Common Base64 Errors

### Error 1: Invalid Padding

❌ **Wrong**:
```
SGVsbG8sIFdvcmxkIQ=  (Only 1 padding, should be 2 or 0)
```

✅ **Correct**:
```
SGVsbG8sIFdvcmxkIQ==  (2 padding characters)
```

### Error 2: Invalid Characters

❌ **Wrong**:
```
SGVsbG8@IFdvcmxkIQ==  (@ is not a Base64 character)
```

✅ **Correct**:
```
SGVsbG8sIFdvcmxkIQ==  (Only A-Za-z0-9+/ and =)
```

### Error 3: Using Standard Base64 in URLs

❌ **Wrong**:
```
https://example.com/token=abc+def/xyz==  (+ and / break URLs)
```

✅ **Correct** (Base64URL):
```
https://example.com/token=abc-def_xyz  (- and _ are URL-safe)
```

**Validate and fix**: [Base64 Encoder with Error Detection](https://orbit2x.com/encoder)

---

## Tools & Resources

### Online Base64 Tools

- **[Base64 Encoder/Decoder](https://orbit2x.com/encoder)** - Encode/decode text, files, images
- **[Image to Base64](https://orbit2x.com/imagebase64)** - Convert images to Base64 data URIs
- **[JWT Decoder](https://orbit2x.com/jwt-decoder)** - Decode JWT tokens (Base64URL)
- **[Hash Generator](https://orbit2x.com/hash)** - Generate MD5, SHA-256 hashes
- **[Checksum Calculator](https://orbit2x.com/checksum-calculator)** - File integrity verification
- **[All Tools](https://orbit2x.com/tools)** - Complete developer toolkit

### Base64 Libraries

**JavaScript/Node.js**:
- Native `btoa()` / `atob()` (browser)
- `Buffer.from()` / `Buffer.toString('base64')` (Node.js)

**Python**:
- Built-in `base64` module (standard library)

**Go**:
- `encoding/base64` (standard library)

**PHP**:
- `base64_encode()` / `base64_decode()` (built-in)

---

## FAQ

### Q: Is Base64 encoding secure?

**A**: **No**, Base64 is NOT encryption! It's a reversible encoding scheme. Anyone can decode Base64 data. Always use encryption (AES, RSA) for sensitive data.

### Q: Why does Base64 increase file size by 33%?

**A**: Base64 converts 3 bytes (24 bits) into 4 characters. Each character represents 6 bits, so 4 characters = 24 bits. This creates a 4/3 size ratio (33% increase).

### Q: What's the difference between Base64 and Base64URL?

**A**: **Base64URL** replaces `+` with `-`, `/` with `_`, and removes padding `=` to make it safe for URLs and filenames. Used in JWT, OAuth tokens.

### Q: Can I decode Base64 without knowing the original format?

**A**: Yes, but you won't know if it's text, binary, image, etc. Base64 only encodes data - it doesn't store metadata about the original format.

### Q: How do I encode images to Base64 for HTML?

**A**: Use [Image to Base64 Converter](https://orbit2x.com/imagebase64) to generate data URIs like `data:image/png;base64,iVBORw0KGgo...`

### Q: Why do some Base64 strings end with = or ==?

**A**: **Padding** ensures the output length is divisible by 4. If input bytes aren't divisible by 3, padding is added (1 byte → `==`, 2 bytes → `=`).

---

## Related Tools

- **[Image to Base64](https://orbit2x.com/imagebase64)** - Convert images to Base64 data URIs
- **[JWT Decoder](https://orbit2x.com/jwt-decoder)** - Decode JWT tokens
- **[Hash Generator](https://orbit2x.com/hash)** - MD5, SHA-256, SHA-512 hashing
- **[Checksum Calculator](https://orbit2x.com/checksum-calculator)** - File integrity verification
- **[Hex to Text](https://orbit2x.com/converter)** - Hex encoding/decoding
- **[URL Encoder](https://orbit2x.com/converter)** - URL encoding/decoding
- **[All Tools](https://orbit2x.com/tools)** - Complete developer toolkit

---

**Made with ❤️ by [Orbit2x](https://orbit2x.com) - Free Developer Tools**

**Encode/Decode now**: [Base64 Encoder](https://orbit2x.com/encoder)
