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

use tar::{Builder, Archive};
use walkdir::WalkDir;
use ring::{aead::{self, BoundKey, SealingKey, UnboundKey, NonceSequence}, pbkdf2, rand::{SystemRandom, SecureRandom}};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use crc32fast::Hasher;
use rayon::prelude::*;

// --- [상수 및 에러 코드] ---
const CHUNK_SIZE: usize = 100 * 1024 * 1024; 
const DATA_SHARDS: usize = 10;
const PARITY_SHARDS: usize = 2;
const NONCE_LEN: usize = 12;

// 에러 코드 정의
// 0: 성공
// 1: 대상 경로(파일/폴더) 찾을 수 없음
// 2: 데이터 읽기 실패 (파일 오픈, 헤더 인식 등)
// 3: 암호화/복호화 실패 (키 유도, 태그 불일치 등)
// 4: 리드 솔로몬/CRC 오류
// 5: 파일 쓰기, 생성 또는 삭제 실패
// 6: 멀티스레드/병렬 처리 환경 오류

#[unsafe(no_mangle)]
pub extern "C" fn dll_locking(src_path_ptr: *const u16, password_ptr: *const c_char) -> u8 {
    let src_path = unsafe {
        if src_path_ptr.is_null() { return 1; }
        let mut len = 0; while *src_path_ptr.offset(len) != 0 { len += 1; }
        OsString::from_wide(std::slice::from_raw_parts(src_path_ptr, len as usize)).to_string_lossy().into_owned()
    };
    let password = unsafe {
        if password_ptr.is_null() { return 3; }
        CStr::from_ptr(password_ptr).to_str().unwrap_or("")
    };
    match locking_internal(&src_path, password) { Ok(_) => 0, Err(e) => e }
}

#[unsafe(no_mangle)]
pub extern "C" fn dll_unlocking(lock_file_path_ptr: *const u16, password_ptr: *const c_char) -> u8 {
    let lock_file_path = unsafe {
        if lock_file_path_ptr.is_null() { return 1; }
        let mut len = 0; while *lock_file_path_ptr.offset(len) != 0 { len += 1; }
        OsString::from_wide(std::slice::from_raw_parts(lock_file_path_ptr, len as usize)).to_string_lossy().into_owned()
    };
    let password = unsafe {
        if password_ptr.is_null() { return 3; }
        CStr::from_ptr(password_ptr).to_str().unwrap_or("")
    };
    match unlocking_internal(&lock_file_path, password) { Ok(_) => 0, Err(e) => e }
}

struct StreamingWriter {
    tx: SyncSender<Vec<u8>>,
    pool_rx: Receiver<Vec<u8>>,
}

impl Write for StreamingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut vec = self.pool_rx.try_recv().unwrap_or_else(|_| Vec::with_capacity(CHUNK_SIZE));
        vec.clear();
        vec.extend_from_slice(buf);
        self.tx.send(vec).map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
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

// --- [암호화 및 RS 로직 생략되지 않은 핵심 함수] ---

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
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)?;
        let mut sealing_key = SealingKey::new(unbound_key, OneNonceSequence(nonce));
        sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut data)?;
        Ok(data)
    }
    pub fn decrypt(&self, nonce_bytes: &[u8], mut data: Vec<u8>) -> Result<Vec<u8>, ring::error::Unspecified> {
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &self.key_bytes)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)?;
        let mut opening_key = aead::OpeningKey::new(unbound_key, OneNonceSequence(nonce));
        let decrypted_data = opening_key.open_in_place(aead::Aad::empty(), &mut data)?;
        Ok(decrypted_data.to_vec())
    }
}

fn encode_rs_mt(data: Vec<u8>, pool: &rayon::ThreadPool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let actual_len = data.len();
    if actual_len == 0 { return Err("Empty data".into()); }

    // 1. 샤드 크기 결정 (최소 1바이트 보장 및 짝수 정렬)
    let mut shard_size = (actual_len + DATA_SHARDS - 1) / DATA_SHARDS;
    if shard_size == 0 { shard_size = 1; }
    if shard_size % 2 != 0 { shard_size += 1; }

    // 2. 전체 필요 데이터 크기 (DATA_SHARDS * shard_size) 사용 안함
    let _total_data_size = DATA_SHARDS * shard_size;

    // 3. 데이터를 샤드 크기에 맞게 패딩 및 분할
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

    // 4. RS 인코딩
    let mut encoder = ReedSolomonEncoder::new(DATA_SHARDS, PARITY_SHARDS, shard_size)?;
    for s in &all_shards {
        encoder.add_original_shard(s)?;
    }
    let result = encoder.encode()?;
    
    // 5. 결과 패키징 (병렬 CRC 계산)
    let final_payload = pool.install(|| {
        let recovery_shards: Vec<Vec<u8>> = result.recovery_iter().map(|s| s.to_vec()).collect();
        let combined: Vec<Vec<u8>> = all_shards.into_iter().chain(recovery_shards).collect();

        let processed: Vec<Vec<u8>> = combined.into_par_iter().map(|mut shard| {
            let mut hasher = Hasher::new();
            hasher.update(&shard);
            shard.extend_from_slice(&hasher.finalize().to_le_bytes());
            shard
        }).collect();

        let mut buffer = Vec::new();
        for s in processed { buffer.extend_from_slice(&s); }
        // 복구를 위해 실제 데이터 길이를 저장
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
    let shard_chunks: Vec<&[u8]> = payload[..data_len_pos].chunks(shard_full_len).collect();
    let verified: Vec<(usize, bool, &[u8])> = pool.install(|| {
        shard_chunks.into_par_iter().enumerate().map(|(idx, full)| {
            let (content, crc_bytes) = full.split_at(shard_size);
            let mut hasher = Hasher::new(); hasher.update(content);
            (idx, hasher.finalize().to_le_bytes() == crc_bytes, content)
        }).collect()
    });
    let mut decoder = ReedSolomonDecoder::new(DATA_SHARDS, PARITY_SHARDS, shard_size)?;
    let mut valid_original = HashMap::new();
    for (idx, is_ok, content) in verified {
        if is_ok {
            if idx < DATA_SHARDS {
                decoder.add_original_shard(idx, content)?;
                valid_original.insert(idx, content.to_vec());
            } else { decoder.add_recovery_shard(idx - DATA_SHARDS, content)?; }
        }
    }
    let result = decoder.decode()?;
    let restored: HashMap<usize, &[u8]> = result.restored_original_iter().collect();
    let mut final_data = Vec::new();
    for i in 0..DATA_SHARDS {
        if let Some(s) = valid_original.get(&i) { final_data.extend_from_slice(s); }
        else if let Some(s) = restored.get(&i) { final_data.extend_from_slice(s); }
        else { return Err("RS Recovery Failed".into()); }
    }
    final_data.truncate(actual_len);
    Ok(final_data)
}

// --- [핵심 로직: Locking] ---

pub fn locking_internal(src_path: &str, password: &str) -> Result<(), u8> {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get().saturating_sub(2).max(1)).build().map_err(|_| 6u8)?;
    let path = Path::new(src_path);
    if !path.exists() { return Err(1); }
    let is_dir = path.is_dir();
    let file_name = path.file_name().ok_or(1u8)?.to_str().ok_or(1u8)?.as_bytes();

    let mut out_path = PathBuf::from(src_path);
    out_path.as_mut_os_string().push(".lock");
    let mut writer = BufWriter::with_capacity(1024 * 1024, File::create(&out_path).map_err(|_| 5u8)?);

    let key_mgr = KeyManager::new();
    let encryptor = Encryptor::new(key_mgr.derive_key(password));
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).map_err(|_| 3u8)?;

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
            let mut arch = Builder::new(StreamingWriter { tx, pool_rx });
            for entry in WalkDir::new(&src_p).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path();
                let name = p.strip_prefix(Path::new(&src_p)).unwrap();
                if p.is_file() {
                    if let Ok(f) = File::open(p) {
                        // 1. 파일 메타데이터에서 헤더 생성
                        if let Ok(metadata) = f.metadata() {
                            let mut header = tar::Header::new_gnu();
                            header.set_metadata(&metadata);
                            
                            // 2. BufReader를 사용하여 스트리밍 읽기
                            let mut reader = BufReader::with_capacity(1024 * 1024, f);
                            
                            // 3. append_data를 통해 데이터 밀어넣기
                            let _ = arch.append_data(&mut header, name, &mut reader);
                        }
                    }
                } else if p.is_dir() && name.as_os_str() != "" { let _ = arch.append_dir(name, p); }
            }
            let _ = arch.finish();
        } else {
            if let Ok(f) = File::open(&src_p) {
                let mut r = BufReader::with_capacity(1024*1024, f);
                loop {
                    let mut v = pool_rx.try_recv().unwrap_or_else(|_| vec![0u8; CHUNK_SIZE]);
                    v.resize(CHUNK_SIZE, 0);
                    match r.read(&mut v) { Ok(0) | Err(_) => break, Ok(n) => { v.truncate(n); if tx.send(v).is_err() { break; } } }
                }
            }
        }
    });

    // locking_internal 함수 내부 메인 루프
    while let Ok(chunk) = rx.recv() {
        if chunk.is_empty() { continue; } // 빈 데이터 스킵
        
        let enc = encryptor.encrypt(&nonce, chunk.clone()).map_err(|_| 3u8)?;
        // RS 인코딩 호출 (여기서 4번 에러 발생 지점)
        let payload = encode_rs_mt(enc, &pool).map_err(|e| {
            eprintln!("RS Encoding Error: {}", e); // 구체적인 에러 메시지 출력
            4u8
        })?;
    
        writer.write_all(&(payload.len() as u64).to_le_bytes()).map_err(|_| 5u8)?;
        writer.write_all(&payload).map_err(|_| 5u8)?;
        
        let mut old = chunk;
        old.clear();
        let _ = pool_tx.try_send(old);
    }
    writer.flush().map_err(|_| 5u8)?;
    if is_dir { fs::remove_dir_all(src_path).ok(); } else { fs::remove_file(src_path).ok(); }
    Ok(())
}

// --- [핵심 로직: Unlocking] ---

pub fn unlocking_internal(lock_file_path: &str, password: &str) -> Result<(), u8> {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get().saturating_sub(2).max(1)).build().map_err(|_| 6u8)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(lock_file_path).map_err(|_| 2u8)?);
    
    let mut magic = [0u8; 4]; reader.read_exact(&mut magic).map_err(|_| 2u8)?;
    if &magic != b"LSTR" { return Err(2); }

    let mut t_buf = [0u8; 1]; reader.read_exact(&mut t_buf).map_err(|_| 2u8)?;
    let mut nl_buf = [0u8; 4]; reader.read_exact(&mut nl_buf).map_err(|_| 2u8)?;
    let mut name_buf = vec![0u8; u32::from_le_bytes(nl_buf) as usize];
    reader.read_exact(&mut name_buf).map_err(|_| 2u8)?;
    let mut salt = [0u8; 16]; reader.read_exact(&mut salt).map_err(|_| 2u8)?;
    let mut nonce = [0u8; NONCE_LEN]; reader.read_exact(&mut nonce).map_err(|_| 2u8)?;

    let encryptor = Encryptor::new(KeyManager::from_existing(salt).derive_key(password));
    let mut out_path = PathBuf::from(lock_file_path);
    out_path.set_file_name(String::from_utf8(name_buf).map_err(|_| 2u8)?);

    let (tx, rx) = sync_channel::<Vec<u8>>(3);
    if t_buf[0] == 0 {
        let out_p = out_path.clone();
        let handle = thread::spawn(move || {
            let mut arch = Archive::new(ChannelReader { rx, current_chunk: None });
            arch.unpack(out_p)
        });
        loop {
            let mut l_buf = [0u8; 8];
            if reader.read_exact(&mut l_buf).is_err() { break; }
            let mut b_data = vec![0u8; u64::from_le_bytes(l_buf) as usize];
            reader.read_exact(&mut b_data).map_err(|_| 2u8)?;
            let dec = encryptor.decrypt(&nonce, decode_rs_mt(b_data, &pool).map_err(|_| 4u8)?).map_err(|_| 3u8)?;
            if tx.send(dec).is_err() { break; }
        }
        drop(tx); handle.join().map_err(|_| 6u8)?.map_err(|_| 5u8)?;
    } else {
        let mut out_f = BufWriter::with_capacity(1024 * 1024, File::create(&out_path).map_err(|_| 5u8)?);
        loop {
            let mut l_buf = [0u8; 8];
            if reader.read_exact(&mut l_buf).is_err() { break; }
            let mut b_data = vec![0u8; u64::from_le_bytes(l_buf) as usize];
            reader.read_exact(&mut b_data).map_err(|_| 2u8)?;
            let dec = encryptor.decrypt(&nonce, decode_rs_mt(b_data, &pool).map_err(|_| 4u8)?).map_err(|_| 3u8)?;
            out_f.write_all(&dec).map_err(|_| 5u8)?;
        }
        out_f.flush().map_err(|_| 5u8)?;
    }
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