# FileLocker
<img width="900" height="540" alt="image" src="https://github.com/user-attachments/assets/eebd4b98-f221-4719-9b51-7b87149eae04" />



# Key Features
1. Powered by AES-256-GCM authenticated encryption for maximum security.
2. Integrated $N=10, K=2$ Reed-Solomon erasure coding. Even if up to 20% of the encrypted file is corrupted, your data remains fully recoverable.
3. Multi-threaded processing using Rust's Rayon and streaming architecture (100MB chunks) for handling large files efficiently.


# How to Use
1. Select Target: Drag and drop a file/folder or use the 'Open' button to select a path.
2. Mode Select: The app automatically toggles between Lock and Unlock based on the file extension (.lock).
3. Password: Click Start and enter your secure password.
4. Done: Once complete, the original file is securely replaced with an encrypted/decrypted version.
