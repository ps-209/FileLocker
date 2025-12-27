# FileLocker
<img width="900" height="540" alt="스크린샷 2025-12-27 232742" src="https://github.com/user-attachments/assets/60a9042f-bd37-4880-8475-1df82c4a6041" />

Key Features
1. Powered by AES-256-GCM authenticated encryption for maximum security.
2. Integrated $N=10, K=2$ Reed-Solomon erasure coding. Even if up to 20% of the encrypted file is corrupted, your data remains fully recoverable.
3. Multi-threaded processing using Rust's Rayon and streaming architecture (100MB chunks) for handling large files efficiently.

How to Use
1. Select Target: Drag and drop a file/folder or use the 'Open' button to select a path.
2. Mode Select: The app automatically toggles between Lock and Unlock based on the file extension (.lock).
3. Password: Click Start and enter your secure password.
4. Done: Once complete, the original file is securely replaced with an encrypted/decrypted version.
