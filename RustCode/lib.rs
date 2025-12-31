use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write, Cursor};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ffi::{CStr, OsString};
use std::os::raw::c_char;
use std::os::windows::ffi::OsStringExt;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};

use tar::{Builder, Archive};
use walkdir::WalkDir;
use ring::{aead::{self, BoundKey, SealingKey, UnboundKey, NonceSequence}, pbkdf2, rand::{SystemRandom, SecureRandom}};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use crc32fast::Hasher;
use rayon::prelude::*;

// --- [상수 설정] ---
const CHUNK_SIZE: usize = 100 * 1024 * 1024; // 100MB
const DATA_SHARDS: usize = 10;
const PARITY_SHARDS: usize = 2;
const NONCE_LEN: usize = 12;

static CANCEL_FLAG: AtomicBool = AtomicBool::new(false);

type ProgressCallback = extern "C" fn(f32);

// --- [DLL 인터페이스] ---

#[unsafe(no_mangle)]
pub extern "C" fn dll_locking(src_path_ptr: *const u16, password_ptr: *const c_char, total_size: u64, progress_callback: ProgressCallback) -> u8 {
    let src_path = unsafe {
        if src_path_ptr.is_null() { return 1; }
        let mut len = 0; while *src_path_ptr.offset(len) != 0 { len += 1; }
        OsString::from_wide(std::slice::from_raw_parts(src_path_ptr, len as usize)).to_string_lossy().into_owned()
    };
    let password = unsafe {
        if password_ptr.is_null() { return 3; }
        CStr::from_ptr(password_ptr).to_str().unwrap_or("")
    };
    match locking_internal(&src_path, password, total_size, progress_callback) { Ok(_) => 0, Err(e) => e }
}

#[unsafe(no_mangle)]
pub extern "C" fn dll_unlocking(lock_file_path_ptr: *const u16, password_ptr: *const c_char, total_lock_size: u64, progress_callback: ProgressCallback) -> u8 {
    let lock_file_path = unsafe {
        if lock_file_path_ptr.is_null() { return 1; }
        let mut len = 0; while *lock_file_path_ptr.offset(len) != 0 { len += 1; }
        OsString::from_wide(std::slice::from_raw_parts(lock_file_path_ptr, len as usize)).to_string_lossy().into_owned()
    };
    let password = unsafe {
        if password_ptr.is_null() { return 3; }
        CStr::from_ptr(password_ptr).to_str().unwrap_or("")
    };
    match unlocking_internal(&lock_file_path, password, total_lock_size, progress_callback) { Ok(_) => 0, Err(e) => e }
}

#[unsafe(no_mangle)]
pub extern "C" fn dll_cancel_operation() {
    CANCEL_FLAG.store(true, Ordering::SeqCst);
}

// --- [스트리밍 최적화 라이터] ---

struct StreamingWriter {
    tx: SyncSender<Vec<u8>>,
    pool_rx: Receiver<Vec<u8>>,
    internal_buffer: Vec<u8>, // 속도 최적화를 위한 버퍼링
}

impl Write for StreamingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.internal_buffer.extend_from_slice(buf);

        // 버퍼가 100MB를 넘을 때만 암호화 엔진으로 전송
        while self.internal_buffer.len() >= CHUNK_SIZE {
            let mut chunk = self.pool_rx.try_recv().unwrap_or_else(|_| Vec::with_capacity(CHUNK_SIZE));
            chunk.clear();
            chunk.extend_from_slice(&self.internal_buffer[..CHUNK_SIZE]);
            
            self.tx.send(chunk).map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            self.internal_buffer.drain(..CHUNK_SIZE);
        }
        Ok(buf.len())
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        // 루프 종료 후 남은 찌꺼기 데이터 전송
        if !self.internal_buffer.is_empty() {
            let chunk = self.internal_buffer.clone();
            let _ = self.tx.send(chunk);
            self.internal_buffer.clear();
        }
        Ok(())
    }
}

struct ChannelReader { rx: Receiver<Vec<u8>>, current_chunk: Option<Cursor<Vec<u8>>> }
impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(ref mut cursor) = self.current_chunk {
                let n = cursor.read(buf)?;
                if n > 0 { return Ok(n); }
            }
            match self.rx.recv() {
                Ok(data) => self.current_chunk = Some(Cursor::new(data)),
                Err(_) => return Ok(0),
            }
        }
    }
}

// --- [보안 및 RS 모듈] ---

pub struct KeyManager { pub salt: [u8; 16], pub iterations: NonZeroU32 }
impl KeyManager {
    pub fn new() -> Self {
        let mut salt = [0u8; 16];
        SystemRandom::new().fill(&mut salt).unwrap();
        Self { salt, iterations: NonZeroU32::new(100_000).unwrap() }
    }
    pub fn from_existing(salt: [u8; 16]) -> Self {
        Self { salt, iterations: NonZeroU32::new(100_000).unwrap() }
    }
    pub fn derive_key(&self, password: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, self.iterations, &self.salt, password.as_bytes(), &mut key);
        key
    }
}

struct OneNonceSequence(aead::Nonce);
impl NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        Ok(std::mem::replace(&mut self.0, aead::Nonce::try_assume_unique_for_key(&[0u8; NONCE_LEN])?))
    }
}

pub struct Encryptor { key_bytes: [u8; 32] }
impl Encryptor {
    pub fn new(key: [u8; 32]) -> Self { Self { key_bytes: key } }
    pub fn encrypt(&self, nonce_bytes: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>, ring::error::Unspecified> {
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &self.key_bytes)?;
        let mut sealing_key = SealingKey::new(unbound_key, OneNonceSequence(aead::Nonce::try_assume_unique_for_key(nonce_bytes)?));
        sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut data)?;
        Ok(data)
    }
    pub fn decrypt(&self, nonce_bytes: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>, ring::error::Unspecified> {
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &self.key_bytes)?;
        let mut opening_key = aead::OpeningKey::new(unbound_key, OneNonceSequence(aead::Nonce::try_assume_unique_for_key(nonce_bytes)?));
        let dec = opening_key.open_in_place(aead::Aad::empty(), &mut data)?;
        Ok(dec.to_vec())
    }
}

fn encode_rs_mt(data: Vec<u8>, pool: &rayon::ThreadPool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let actual_len = data.len();
    let mut shard_size = (actual_len + DATA_SHARDS - 1) / DATA_SHARDS;
    if shard_size == 0 { shard_size = 1; }
    if shard_size % 2 != 0 { shard_size += 1; }

    let all_shards: Vec<Vec<u8>> = pool.install(|| {
        (0..DATA_SHARDS).into_par_iter().map(|i| {
            let start = i * shard_size;
            let mut s = vec![0u8; shard_size];
            if start < actual_len {
                let end = std::cmp::min(start + shard_size, actual_len);
                s[..end - start].copy_from_slice(&data[start..end]);
            }
            s
        }).collect()
    });

    let mut encoder = ReedSolomonEncoder::new(DATA_SHARDS, PARITY_SHARDS, shard_size)?;
    for s in &all_shards { encoder.add_original_shard(s)?; }
    let result = encoder.encode()?;
    
    let final_payload = pool.install(|| {
        let combined: Vec<Vec<u8>> = all_shards.into_iter().chain(result.recovery_iter().map(|s| s.to_vec())).collect();
        let processed: Vec<Vec<u8>> = combined.into_par_iter().map(|mut shard| {
            let mut hasher = Hasher::new();
            hasher.update(&shard);
            shard.extend_from_slice(&hasher.finalize().to_le_bytes());
            shard
        }).collect();

        let mut buffer = Vec::new();
        for s in processed { buffer.extend_from_slice(&s); }
        buffer.extend_from_slice(&(actual_len as u64).to_le_bytes());
        buffer
    });
    Ok(final_payload)
}

fn decode_rs_mt(payload: Vec<u8>, pool: &rayon::ThreadPool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data_len_pos = payload.len() - 8;
    let actual_len = u64::from_le_bytes(payload[data_len_pos..].try_into()?) as usize;
    let shard_full_len = data_len_pos / (DATA_SHARDS + PARITY_SHARDS);
    let shard_size = shard_full_len - 4;
    
    let verified: Vec<(usize, bool, &[u8])> = pool.install(|| {
        payload[..data_len_pos].chunks(shard_full_len).enumerate().par_bridge().map(|(idx, full)| {
            let (content, crc) = full.split_at(shard_size);
            let mut h = Hasher::new(); h.update(content);
            (idx, h.finalize().to_le_bytes() == crc, content)
        }).collect()
    });

    let mut decoder = ReedSolomonDecoder::new(DATA_SHARDS, PARITY_SHARDS, shard_size)?;
    let mut shards_map = HashMap::new();
    for (idx, ok, content) in verified {
        if ok {
            if idx < DATA_SHARDS { decoder.add_original_shard(idx, content)?; }
            else { decoder.add_recovery_shard(idx - DATA_SHARDS, content)?; }
            shards_map.insert(idx, content.to_vec());
        }
    }

    let result = decoder.decode()?;
    let restored: HashMap<usize, &[u8]> = result.restored_original_iter().collect();
    let mut final_data = Vec::new();
    for i in 0..DATA_SHARDS {
        if let Some(s) = shards_map.get(&i) { final_data.extend_from_slice(s); }
        else if let Some(s) = restored.get(&i) { final_data.extend_from_slice(s); }
        else { return Err("Recovery Failed".into()); }
    }
    final_data.truncate(actual_len);
    Ok(final_data)
}

// --- [핵심 로직: Locking] ---

pub fn locking_internal(src_path: &str, password: &str, total_size: u64, progress_callback: ProgressCallback) -> Result<(), u8> {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get().saturating_sub(2).max(1)).build().map_err(|_| 6u8)?;
    let path = Path::new(src_path);
    if !path.exists() { return Err(1); }
    
    CANCEL_FLAG.store(false, Ordering::SeqCst);
    let mut run_result: Result<(), u8> = Ok(());
    let mut processed_size: u64 = 0;

    let is_dir = path.is_dir();
    let file_name = path.file_name().ok_or(1u8)?.to_str().ok_or(1u8)?.as_bytes();
    let mut out_path = PathBuf::from(src_path);
    out_path.as_mut_os_string().push(".lock");

    let mut writer = BufWriter::with_capacity(1024 * 1024, File::create(&out_path).map_err(|_| 5u8)?);
    let key_mgr = KeyManager::new();
    let encryptor = Encryptor::new(key_mgr.derive_key(password));
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).map_err(|_| 3u8)?;

    // 헤더 작성
    writer.write_all(b"LSTR").map_err(|_| 5u8)?;
    writer.write_all(&[if is_dir { 0 } else { 1 }]).map_err(|_| 5u8)?;
    writer.write_all(&(file_name.len() as u32).to_le_bytes()).map_err(|_| 5u8)?;
    writer.write_all(file_name).map_err(|_| 5u8)?;
    writer.write_all(&key_mgr.salt).map_err(|_| 5u8)?;
    writer.write_all(&nonce).map_err(|_| 5u8)?;

    let (tx, rx) = sync_channel::<Vec<u8>>(3);
    let (pool_tx, pool_rx) = sync_channel::<Vec<u8>>(3);
    let src_p = src_path.to_string();

    thread::spawn(move || {
        if is_dir {
            let mut sw = StreamingWriter { tx, pool_rx, internal_buffer: Vec::with_capacity(CHUNK_SIZE) };
            let mut arch = Builder::new(&mut sw);
            for entry in WalkDir::new(&src_p).into_iter().filter_map(|e| e.ok()) {
                if CANCEL_FLAG.load(Ordering::SeqCst) { return; }
                let p = entry.path();
                let name = p.strip_prefix(Path::new(&src_p)).unwrap();
                if p.is_file() {
                    if let Ok(f) = File::open(p) {
                        if let Ok(meta) = f.metadata() {
                            let mut h = tar::Header::new_gnu(); h.set_metadata(&meta);
                            let _ = arch.append_data(&mut h, name, BufReader::new(f));
                        }
                    }
                } else if p.is_dir() && name.as_os_str() != "" { let _ = arch.append_dir(name, p); }
            }
            let _ = arch.finish();
            drop(arch);
            let _ = sw.flush(); // 마지막 버퍼 비우기
        } else if let Ok(f) = File::open(&src_p) {
            let mut r = BufReader::new(f);
            loop {
                if CANCEL_FLAG.load(Ordering::SeqCst) { return; }
                let mut v = pool_rx.try_recv().unwrap_or_else(|_| vec![0u8; CHUNK_SIZE]);
                v.resize(CHUNK_SIZE, 0);
                match r.read(&mut v) { Ok(0) | Err(_) => break, Ok(n) => { v.truncate(n); if tx.send(v).is_err() { break; } } }
            }
        }
    });

    while let Ok(chunk) = rx.recv() {
        if CANCEL_FLAG.load(Ordering::SeqCst) { run_result = Err(100); break; }
        if chunk.is_empty() { continue; }

        let chunk_len = chunk.len() as u64;
        let enc = encryptor.encrypt(&nonce, chunk.clone()).map_err(|_| 3u8)?;
        let payload = encode_rs_mt(enc, &pool).map_err(|_| 4u8)?;

        writer.write_all(&(payload.len() as u64).to_le_bytes()).map_err(|_| 5u8)?;
        writer.write_all(&payload).map_err(|_| 5u8)?;

        processed_size += chunk_len;
        if total_size > 0 { progress_callback((processed_size as f32 / total_size as f32).min(1.0)); }
        
        let mut old = chunk; old.clear(); let _ = pool_tx.try_send(old);
    }

    writer.flush().ok(); drop(writer);
    if let Err(e) = run_result { fs::remove_file(&out_path).ok(); return Err(e); }
    
    progress_callback(1.0);
    if is_dir { fs::remove_dir_all(src_path).ok(); } else { fs::remove_file(src_path).ok(); }
    Ok(())
}

// --- [핵심 로직: Unlocking] ---

pub fn unlocking_internal(lock_file_path: &str, password: &str, total_lock_size: u64, progress_callback: ProgressCallback) -> Result<(), u8> {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get().saturating_sub(2).max(1)).build().map_err(|_| 6u8)?;
    let lock_file = File::open(lock_file_path).map_err(|_| 2u8)?;
    
    CANCEL_FLAG.store(false, Ordering::SeqCst);
    let mut reader = BufReader::new(lock_file);
    let mut processed_size: u64 = 0;
    let mut run_result: Result<(), u8> = Ok(());

    let mut magic = [0u8; 4]; reader.read_exact(&mut magic).map_err(|_| 2u8)?;
    if &magic != b"LSTR" { return Err(2); }

    let mut t_buf = [0u8; 1]; reader.read_exact(&mut t_buf).map_err(|_| 2u8)?;
    let mut nl_buf = [0u8; 4]; reader.read_exact(&mut nl_buf).map_err(|_| 2u8)?;
    let mut name_buf = vec![0u8; u32::from_le_bytes(nl_buf) as usize];
    reader.read_exact(&mut name_buf).map_err(|_| 2u8)?;
    let mut salt = [0u8; 16]; reader.read_exact(&mut salt).map_err(|_| 2u8)?;
    let mut nonce = [0u8; NONCE_LEN]; reader.read_exact(&mut nonce).map_err(|_| 2u8)?;
    
    processed_size += 4 + 1 + 4 + name_buf.len() as u64 + 16 + NONCE_LEN as u64;

    let encryptor = Encryptor::new(KeyManager::from_existing(salt).derive_key(password));
    let mut out_path = PathBuf::from(lock_file_path);
    out_path.set_file_name(String::from_utf8(name_buf).map_err(|_| 2u8)?);

    let (tx, rx) = sync_channel::<Vec<u8>>(3);

    if t_buf[0] == 0 { // 폴더 모드
        let out_p = out_path.clone();
        let handle = thread::spawn(move || {
            let mut arch = Archive::new(ChannelReader { rx, current_chunk: None });
            arch.unpack(out_p)
        });

        loop {
            if CANCEL_FLAG.load(Ordering::SeqCst) { run_result = Err(100); break; }
            let mut l_buf = [0u8; 8];
            if reader.read_exact(&mut l_buf).is_err() { break; }
            let payload_len = u64::from_le_bytes(l_buf);
            let mut data = vec![0u8; payload_len as usize];
            reader.read_exact(&mut data).map_err(|_| 2u8)?;

            let dec = encryptor.decrypt(&nonce, decode_rs_mt(data, &pool).map_err(|_| 4u8)?).map_err(|_| 3u8)?;
            if tx.send(dec).is_err() { break; }

            processed_size += 8 + payload_len;
            progress_callback((processed_size as f32 / total_lock_size as f32).min(1.0));
        }
        drop(tx); handle.join().ok();
    } else { // 파일 모드
        let mut out_f = BufWriter::new(File::create(&out_path).map_err(|_| 5u8)?);
        loop {
            if CANCEL_FLAG.load(Ordering::SeqCst) { run_result = Err(100); break; }
            let mut l_buf = [0u8; 8];
            if reader.read_exact(&mut l_buf).is_err() { break; }
            let payload_len = u64::from_le_bytes(l_buf);
            let mut data = vec![0u8; payload_len as usize];
            reader.read_exact(&mut data).map_err(|_| 2u8)?;

            let dec = encryptor.decrypt(&nonce, decode_rs_mt(data, &pool).map_err(|_| 4u8)?).map_err(|_| 3u8)?;
            out_f.write_all(&dec).map_err(|_| 5u8)?;

            processed_size += 8 + payload_len;
            progress_callback((processed_size as f32 / total_lock_size as f32).min(1.0));
        }
        out_f.flush().ok(); drop(out_f);
    }
    
    if let Err(e) = run_result {
        if out_path.is_dir() { fs::remove_dir_all(&out_path).ok(); }
        else { fs::remove_file(&out_path).ok(); }
        return Err(e);
    }

    progress_callback(1.0);
    fs::remove_file(lock_file_path).ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        println!("he");
    }
}