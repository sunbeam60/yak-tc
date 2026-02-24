//! Total Commander WCX packer plugin for Yak container files.

mod config;

use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs::{self, File};
use std::io::{Read as _, Write};
use std::panic;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;

use wcxhead::{
    tHeaderData, tHeaderDataEx, tOpenArchiveData, PackDefaultParamStruct, E_BAD_DATA,
    E_EABORTED, E_ECLOSE, E_ECREATE, E_END_ARCHIVE, E_EOPEN, E_EREAD, E_EWRITE, E_NO_FILES,
    PK_CAPS_BY_CONTENT, PK_CAPS_DELETE, PK_CAPS_ENCRYPT, PK_CAPS_MULTIPLE, PK_CAPS_NEW,
    PK_CAPS_OPTIONS, PK_EXTRACT, PK_SKIP,
};
use windows::Win32::Foundation::HWND;
use yak::{CreateOptions, EntryType, OpenMode, YakDefault, YakError};

use config::PackerConfig;

static GLOBAL_PROCESS_DATA_PROC: Mutex<Option<ProcessDataProc>> = Mutex::new(None);
static GLOBAL_CHANGE_VOL_PROC: Mutex<Option<ChangeVolProc>> = Mutex::new(None);
static GLOBAL_CRYPT_PROC: Mutex<Option<PkCryptProc>> = Mutex::new(None);
static GLOBAL_CRYPT_NR: Mutex<c_int> = Mutex::new(0);
static CONFIG: Mutex<PackerConfig> = Mutex::new(PackerConfig::DEFAULT);
static INI_PATH: Mutex<String> = Mutex::new(String::new());

// ────────────────────────────────────────────────────────────
// Callback types (kept as our own — wcxhead uses *mut char
// instead of *mut c_char, and omits `unsafe`)
// ────────────────────────────────────────────────────────────

type ChangeVolProc = unsafe extern "system" fn(*mut c_char, c_int) -> c_int;
type ProcessDataProc = unsafe extern "system" fn(*mut c_char, c_int) -> c_int;
type PkCryptProc = unsafe extern "system" fn(c_int, c_int, *mut c_char, *mut c_char, c_int) -> c_int;

const FILE_ATTRIBUTE_DIRECTORY: c_int = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: c_int = 0x20;

// ────────────────────────────────────────────────────────────
// Plugin State
// ────────────────────────────────────────────────────────────

struct EntryInfo {
    yak_path: String,
    is_directory: bool,
    size: u64,
}

impl EntryInfo {
    fn tc_path(&self) -> String {
        self.yak_path.replace('/', "\\")
    }
}

struct ArchiveInstance {
    yak: Option<YakDefault>,
    entries: Vec<EntryInfo>,
    current_index: usize,
    archive_path: String,
    process_data_proc: Option<ProcessDataProc>,
    #[allow(dead_code)]
    change_vol_proc: Option<ChangeVolProc>,
}

// ────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok().map(|s| s.to_string())
}

fn copy_to_c_buf(s: &str, buf: &mut [c_char]) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(buf.len() - 1);
    for i in 0..len {
        buf[i] = bytes[i] as c_char;
    }
    buf[len] = 0;
}

fn tc_to_yak_path(tc_path: &str) -> String {
    tc_path.replace('\\', "/")
}

/// Prompt the user for a password via our own dialog.
fn get_password() -> Option<Vec<u8>> {
    let parent = unsafe { windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow() };
    config::show_password_dialog(parent)
}

fn enumerate_entries(yak: &YakDefault, dir_path: &str) -> Vec<EntryInfo> {
    let entries = match yak.list(dir_path) {
        Ok(e) => e,
        Err(_) => {
            return Vec::new();
        }
    };

    let mut result = Vec::new();
    for entry in entries {
        let full_path = if dir_path.is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", dir_path, entry.name)
        };

        match entry.entry_type {
            EntryType::Directory => {
                result.push(EntryInfo {
                    yak_path: full_path.clone(),
                    is_directory: true,
                    size: 0,
                });
                result.extend(enumerate_entries(yak, &full_path));
            }
            EntryType::Stream => {
                let size = match yak.open_stream(&full_path, OpenMode::Read) {
                    Ok(handle) => {
                        let s = yak.stream_length(&handle).unwrap_or(0);
                        let _ = yak.close_stream(handle);
                        s
                    }
                    Err(_) => 0,
                };
                result.push(EntryInfo {
                    yak_path: full_path,
                    is_directory: false,
                    size,
                });
            }
        }
    }
    result
}

unsafe fn parse_string_list(list: *mut c_char) -> Vec<String> {
    let mut result = Vec::new();
    if list.is_null() {
        return result;
    }
    let mut ptr = list;
    loop {
        if unsafe { *ptr } == 0 {
            break;
        }
        let s = unsafe { CStr::from_ptr(ptr) };
        let len = s.to_bytes().len();
        if let Ok(rs) = s.to_str() {
            result.push(rs.to_string());
        }
        ptr = unsafe { ptr.add(len + 1) };
    }
    result
}

// ────────────────────────────────────────────────────────────
// WCX Exports — Archive Reading
// ────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "system" fn OpenArchive(archive_data: *mut tOpenArchiveData) -> *mut c_void {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        if archive_data.is_null() {
            return ptr::null_mut();
        }

        let data = unsafe { &mut *archive_data };
        let arc_name = match unsafe { cstr_to_string(data.ArcName) } {
            Some(s) => s,
            None => {
                data.OpenResult = E_EOPEN;
                return ptr::null_mut();
            }
        };

        let yak = match YakDefault::open(&arc_name, OpenMode::Read) {
            Ok(y) => y,
            Err(YakError::EncryptionRequired(_)) => {
                let pw = match get_password() {
                    Some(p) => p,
                    None => {
                        data.OpenResult = E_EOPEN;
                        return ptr::null_mut();
                    }
                };
                match YakDefault::open_encrypted(&arc_name, OpenMode::Read, &pw) {
                    Ok(y) => y,
                    Err(_) => {
                        data.OpenResult = E_EOPEN;
                        return ptr::null_mut();
                    }
                }
            }
            Err(_) => {
                data.OpenResult = E_EOPEN;
                return ptr::null_mut();
            }
        };

        let entries = enumerate_entries(&yak, "");

        let instance = Box::new(ArchiveInstance {
            yak: Some(yak),
            entries,
            current_index: 0,
            archive_path: arc_name,
            process_data_proc: GLOBAL_PROCESS_DATA_PROC.lock().ok().and_then(|g| *g),
            change_vol_proc: GLOBAL_CHANGE_VOL_PROC.lock().ok().and_then(|g| *g),
        });

        data.OpenResult = 0;
        Box::into_raw(instance) as *mut c_void
    }));

    match result {
        Ok(handle) => handle,
        Err(_) => {
            if !archive_data.is_null() {
                unsafe { (*archive_data).OpenResult = E_BAD_DATA };
            }
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn ReadHeader(
    handle: *mut c_void,
    header: *mut tHeaderData,
) -> c_int {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        if handle.is_null() || header.is_null() {
            return E_BAD_DATA;
        }

        let instance = unsafe { &mut *(handle as *mut ArchiveInstance) };
        if instance.current_index >= instance.entries.len() {
            return E_END_ARCHIVE;
        }

        let entry = &instance.entries[instance.current_index];
        let hdr = unsafe { &mut *header };
        unsafe { ptr::write_bytes(header, 0, 1) };

        copy_to_c_buf(&instance.archive_path, &mut hdr.ArcName);
        copy_to_c_buf(&entry.tc_path(), &mut hdr.FileName);

        hdr.UnpSize = entry.size as c_int;
        hdr.PackSize = entry.size as c_int;
        hdr.FileAttr = if entry.is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };

        0
    }));

    result.unwrap_or(E_BAD_DATA)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn ReadHeaderEx(
    handle: *mut c_void,
    header: *mut tHeaderDataEx,
) -> c_int {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        if handle.is_null() || header.is_null() {
            return E_BAD_DATA;
        }

        let instance = unsafe { &mut *(handle as *mut ArchiveInstance) };
        if instance.current_index >= instance.entries.len() {
            return E_END_ARCHIVE;
        }

        let entry = &instance.entries[instance.current_index];
        let hdr = unsafe { &mut *header };
        unsafe { ptr::write_bytes(header, 0, 1) };

        copy_to_c_buf(&instance.archive_path, &mut hdr.ArcName);
        copy_to_c_buf(&entry.tc_path(), &mut hdr.FileName);

        hdr.UnpSize = entry.size as u32;
        hdr.UnpSizeHigh = (entry.size >> 32) as u32;
        hdr.PackSize = entry.size as u32;
        hdr.PackSizeHigh = (entry.size >> 32) as u32;
        hdr.FileAttr = if entry.is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };

        0
    }));

    result.unwrap_or(E_BAD_DATA)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn ProcessFile(
    handle: *mut c_void,
    operation: c_int,
    dest_path: *mut c_char,
    dest_name: *mut c_char,
) -> c_int {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        if handle.is_null() {
            return E_BAD_DATA;
        }

        let instance = unsafe { &mut *(handle as *mut ArchiveInstance) };
        if instance.current_index >= instance.entries.len() {
            return E_END_ARCHIVE;
        }

        let entry_idx = instance.current_index;
        instance.current_index += 1;

        if operation == PK_SKIP {
            return 0;
        }

        let entry = &instance.entries[entry_idx];

        if entry.is_directory {
            if operation == PK_EXTRACT {
                let dest = if !dest_name.is_null() {
                    unsafe { cstr_to_string(dest_name) }.unwrap_or_default()
                } else if !dest_path.is_null() {
                    let dp = unsafe { cstr_to_string(dest_path) }.unwrap_or_default();
                    format!("{}\\{}", dp, entry.tc_path())
                } else {
                    return 0;
                };
                let _ = fs::create_dir_all(&dest);
            }
            return 0;
        }

        if operation != PK_EXTRACT {
            return 0;
        }

        let dest = if !dest_name.is_null() {
            unsafe { cstr_to_string(dest_name) }.unwrap_or_default()
        } else if !dest_path.is_null() {
            let dp = unsafe { cstr_to_string(dest_path) }.unwrap_or_default();
            format!("{}\\{}", dp, entry.tc_path())
        } else {
            return E_ECREATE;
        };
        if let Some(parent) = Path::new(&dest).parent() {
            let _ = fs::create_dir_all(parent);
        }

        let yak = match instance.yak.as_ref() {
            Some(y) => y,
            None => return E_EREAD,
        };

        let stream_handle = match yak.open_stream(&entry.yak_path, OpenMode::Read) {
            Ok(h) => h,
            Err(_) => return E_EOPEN,
        };

        let mut file = match File::create(&dest) {
            Ok(f) => f,
            Err(_) => {
                let _ = yak.close_stream(stream_handle);
                return E_ECREATE;
            }
        };

        let mut buf = vec![0u8; 65536];
        loop {
            let n = match yak.read(&stream_handle, &mut buf) {
                Ok(n) => n,
                Err(_) => {
                    let _ = yak.close_stream(stream_handle);
                    return E_EREAD;
                }
            };
            if n == 0 {
                break;
            }
            if file.write_all(&buf[..n]).is_err() {
                let _ = yak.close_stream(stream_handle);
                return E_EWRITE;
            }

            if let Some(proc_fn) = instance.process_data_proc {
                if unsafe { proc_fn(ptr::null_mut(), n as c_int) } == 0 {
                    let _ = yak.close_stream(stream_handle);
                    return E_EABORTED;
                }
            }
        }

        let _ = yak.close_stream(stream_handle);
        0
    }));

    result.unwrap_or(E_BAD_DATA)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CloseArchive(handle: *mut c_void) -> c_int {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        if handle.is_null() {
            return E_BAD_DATA;
        }
        let mut instance = unsafe { Box::from_raw(handle as *mut ArchiveInstance) };
        if let Some(yak) = instance.yak.take() {
            match yak.close() {
                Ok(_) => 0,
                Err(_) => E_ECLOSE,
            }
        } else {
            0
        }
    }));

    result.unwrap_or(E_ECLOSE)
}

// ────────────────────────────────────────────────────────────
// WCX Exports — Archive Writing
// ────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PackFiles(
    packed_file: *mut c_char,
    sub_path: *mut c_char,
    src_path: *mut c_char,
    add_list: *mut c_char,
    _flags: c_int,
) -> c_int {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let packed = match unsafe { cstr_to_string(packed_file) } {
            Some(s) => s,
            None => return E_BAD_DATA,
        };
        let src = unsafe { cstr_to_string(src_path) }.unwrap_or_default();
        let sub = unsafe { cstr_to_string(sub_path) }.unwrap_or_default();

        let files = unsafe { parse_string_list(add_list) };
        if files.is_empty() {
            return E_NO_FILES;
        }

        let cfg = CONFIG.lock().map(|g| *g).unwrap_or_default();

        // Get password if encryption is enabled
        let password = if cfg.encrypt {
            match get_password() {
                Some(pw) => Some(pw),
                None => return E_EABORTED,
            }
        } else {
            None
        };

        let yak = if Path::new(&packed).exists() {
            // Open existing archive; try plain first, then encrypted
            match YakDefault::open(&packed, OpenMode::Write) {
                Ok(y) => y,
                Err(YakError::EncryptionRequired(_)) => {
                    let pw = if let Some(ref p) = password {
                        p.clone()
                    } else {
                        match get_password() {
                            Some(p) => p,
                            None => return E_EABORTED,
                        }
                    };
                    match YakDefault::open_encrypted(&packed, OpenMode::Write, &pw) {
                        Ok(y) => y,
                        Err(_) => return E_EOPEN,
                    }
                }
                Err(_) => return E_EOPEN,
            }
        } else {
            let opts = CreateOptions {
                block_index_width: cfg.block_index_width,
                block_size_shift: cfg.block_size_shift,
                compressed_block_size_shift: cfg.compressed_block_size_shift,
                password: password.as_deref(),
            };
            match YakDefault::create(&packed, opts) {
                Ok(y) => y,
                Err(_) => return E_ECREATE,
            }
        };

        let process_data = GLOBAL_PROCESS_DATA_PROC.lock().ok().and_then(|g| *g);

        for file_name in &files {
            let full_src = format!("{}{}", src, file_name);
            let archive_path = if sub.is_empty() {
                tc_to_yak_path(file_name)
            } else {
                let sub_yak = tc_to_yak_path(sub.trim_end_matches('\\'));
                let file_yak = tc_to_yak_path(file_name);
                format!("{}/{}", sub_yak, file_yak)
            };
            // Report current file to TC
            if let Some(proc_fn) = process_data {
                let mut name_buf: Vec<u8> = full_src.bytes().chain(std::iter::once(0)).collect();
                if unsafe { proc_fn(name_buf.as_mut_ptr() as *mut c_char, 0) } == 0 {
                    let _ = yak.close();
                    return E_EABORTED;
                }
            }

            let src_meta = match fs::metadata(&full_src) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if src_meta.is_dir() {
                let _ = yak.mkdir(&archive_path);
            } else {
                if let Some(parent_end) = archive_path.rfind('/') {
                    let mut prefix = String::new();
                    for segment in archive_path[..parent_end].split('/') {
                        if !prefix.is_empty() {
                            prefix.push('/');
                        }
                        prefix.push_str(segment);
                        let _ = yak.mkdir(&prefix);
                    }
                }

                let stream = match yak.create_stream(&archive_path, cfg.compress) {
                    Ok(h) => h,
                    Err(_) => {
                        let _ = yak.close();
                        return E_ECREATE;
                    }
                };

                let mut f = match File::open(&full_src) {
                    Ok(f) => f,
                    Err(_) => {
                        let _ = yak.close_stream(stream);
                        let _ = yak.close();
                        return E_EOPEN;
                    }
                };

                let mut buf = vec![0u8; 65536];
                loop {
                    let n = match f.read(&mut buf) {
                        Ok(n) => n,
                        Err(_) => {
                            let _ = yak.close_stream(stream);
                            let _ = yak.close();
                            return E_EREAD;
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    if yak.write(&stream, &buf[..n]).is_err() {
                        let _ = yak.close_stream(stream);
                        let _ = yak.close();
                        return E_EWRITE;
                    }

                    // Report progress to TC
                    if let Some(proc_fn) = process_data {
                        if unsafe { proc_fn(ptr::null_mut(), n as c_int) } == 0 {
                            let _ = yak.close_stream(stream);
                            let _ = yak.close();
                            return E_EABORTED;
                        }
                    }
                }

                let _ = yak.close_stream(stream);
            }
        }

        match yak.close() {
            Ok(_) => 0,
            Err(_) => E_ECLOSE,
        }
    }));

    result.unwrap_or(E_BAD_DATA)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DeleteFiles(
    packed_file: *mut c_char,
    delete_list: *mut c_char,
) -> c_int {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let packed = match unsafe { cstr_to_string(packed_file) } {
            Some(s) => s,
            None => return E_BAD_DATA,
        };

        let files = unsafe { parse_string_list(delete_list) };
        if files.is_empty() {
            return E_NO_FILES;
        }

        let yak = match YakDefault::open(&packed, OpenMode::Write) {
            Ok(y) => y,
            Err(_) => return E_EOPEN,
        };

        for file_name in &files {
            let yak_path = tc_to_yak_path(file_name);
            if yak.delete_stream(&yak_path).is_err() {
                let _ = yak.rmdir(&yak_path);
            }
        }

        match yak.close() {
            Ok(_) => 0,
            Err(_) => E_ECLOSE,
        }
    }));

    result.unwrap_or(E_BAD_DATA)
}

// ────────────────────────────────────────────────────────────
// WCX Exports — Capabilities & Callbacks
// ────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetPackerCaps() -> c_int {
    PK_CAPS_NEW | PK_CAPS_MULTIPLE | PK_CAPS_DELETE | PK_CAPS_OPTIONS | PK_CAPS_BY_CONTENT | PK_CAPS_ENCRYPT
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetBackgroundFlags() -> c_int {
    wcxhead::BACKGROUND_UNPACK | wcxhead::BACKGROUND_PACK
}

/// Handle value TC uses to mean "set callback globally" (not per-instance).
const INVALID_HANDLE: usize = usize::MAX; // 0xFFFFFFFFFFFFFFFF on 64-bit

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetChangeVolProc(
    handle: *mut c_void,
    change_vol_proc: Option<ChangeVolProc>,
) {
    if handle as usize == INVALID_HANDLE || handle.is_null() {
        if let Ok(mut g) = GLOBAL_CHANGE_VOL_PROC.lock() {
            *g = change_vol_proc;
        }
    } else {
        let instance = unsafe { &mut *(handle as *mut ArchiveInstance) };
        instance.change_vol_proc = change_vol_proc;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetProcessDataProc(
    handle: *mut c_void,
    process_data_proc: Option<ProcessDataProc>,
) {
    if handle as usize == INVALID_HANDLE || handle.is_null() {
        if let Ok(mut g) = GLOBAL_PROCESS_DATA_PROC.lock() {
            *g = process_data_proc;
        }
    } else {
        let instance = unsafe { &mut *(handle as *mut ArchiveInstance) };
        instance.process_data_proc = process_data_proc;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PkSetCryptCallback(
    pk_crypt_proc: Option<PkCryptProc>,
    crypto_nr: c_int,
    _flags: c_int,
) {
    if let Ok(mut g) = GLOBAL_CRYPT_PROC.lock() {
        *g = pk_crypt_proc;
    }
    if let Ok(mut g) = GLOBAL_CRYPT_NR.lock() {
        *g = crypto_nr;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CanYouHandleThisFile(filename: *mut c_char) -> i32 {
    let name = unsafe { cstr_to_string(filename) };
    match name {
        Some(n) if n.to_lowercase().ends_with(".yak") => 1,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PackSetDefaultParams(dps: *mut PackDefaultParamStruct) {
    if dps.is_null() {
        return;
    }
    let dps = unsafe { &*dps };
    let ini_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(dps.DefaultIniName.as_ptr() as *const u8, 260)
    };
    let len = ini_bytes.iter().position(|&b| b == 0).unwrap_or(260);
    if let Ok(ini_str) = std::str::from_utf8(&ini_bytes[..len]) {
        if let Ok(mut path) = INI_PATH.lock() {
            *path = ini_str.to_string();
        }
        let cfg = PackerConfig::load(ini_str);
        if let Ok(mut g) = CONFIG.lock() {
            *g = cfg;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn ConfigurePacker(parent: *mut c_void, _dll_instance: *mut c_void) {
    let ini = INI_PATH.lock().ok().map(|p| p.clone()).unwrap_or_default();
    if ini.is_empty() {
        return;
    }
    let hwnd = HWND(parent);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| config::show_dialog(hwnd, &ini))) {
        Ok(Some(new_cfg)) => {
            if let Ok(mut g) = CONFIG.lock() {
                *g = new_cfg;
            }
        }
        Ok(None) | Err(_) => {}
    }
}
