use tauri::Manager;
use std::fs::{self, OpenOptions};
use std::io::Write;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use rand::RngCore;

#[tauri::command]
fn save_secure_data(handle: tauri::AppHandle, filename: String, data: String) -> Result<(), String> {
    let mut path = handle.path().app_data_dir().map_err(|e| e.to_string())?;
    if !path.exists() {
        fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    }
    path.push(filename);
    fs::write(path, data).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn load_secure_data(handle: tauri::AppHandle, filename: String) -> Result<String, String> {
    let mut path = handle.path().app_data_dir().map_err(|e| e.to_string())?;
    path.push(filename);
    if !path.exists() {
        return Err("File not found".to_string());
    }
    let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
    Ok(data)
}

// Encrypt a file chunk using AES-GCM-256 in Rust
#[tauri::command]
fn encrypt_file_chunk(key: Vec<u8>, chunk: Vec<u8>, chunk_index: u32) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Encryption key must be 32 bytes".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    
    // Create 12-byte nonce: 8 bytes random + 4 bytes chunk index
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes[0..8]);
    nonce_bytes[8..12].copy_from_slice(&chunk_index.to_be_bytes());
    
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, chunk.as_ref()).map_err(|e| e.to_string())?;
    
    // Combine nonce and ciphertext: [Nonce (12 bytes)] + [Ciphertext]
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

// Decrypt a file chunk using AES-GCM-256 in Rust
#[tauri::command]
fn decrypt_file_chunk(key: Vec<u8>, encrypted_chunk: Vec<u8>) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Encryption key must be 32 bytes".to_string());
    }
    if encrypted_chunk.len() < 12 {
        return Err("Encrypted chunk is too short".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    
    // Nonce is first 12 bytes
    let nonce_bytes = &encrypted_chunk[0..12];
    let ciphertext = &encrypted_chunk[12..];
    
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| e.to_string())?;
    Ok(plaintext)
}

// Stream write received decrypted file chunks directly to local downloads folder
#[tauri::command]
fn write_received_chunk(handle: tauri::AppHandle, filename: String, chunk: Vec<u8>, is_first: bool) -> Result<String, String> {
    let mut download_dir = handle.path().download_dir().map_err(|e| e.to_string())?;
    if !download_dir.exists() {
        fs::create_dir_all(&download_dir).map_err(|e| e.to_string())?;
    }
    download_dir.push(&filename);
    
    let file_path_str = download_dir.to_string_lossy().to_string();

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(!is_first)
        .truncate(is_first)
        .open(&download_dir)
        .map_err(|e| e.to_string())?;

    file.write_all(&chunk).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    
    // Return file URI or absolute path so frontend can display/link it
    Ok(file_path_str)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            save_secure_data, 
            load_secure_data,
            encrypt_file_chunk,
            decrypt_file_chunk,
            write_received_chunk
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
