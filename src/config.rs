use std::mem;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{CheckDlgButton, IsDlgButtonChecked, BST_CHECKED};
use windows::Win32::UI::WindowsAndMessaging::*;

// ────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct PackerConfig {
    pub block_index_width: u8,
    pub block_size_shift: u8,
    pub compressed_block_size_shift: u8,
    pub compress: bool,
    pub encrypt: bool,
}

impl PackerConfig {
    pub const DEFAULT: Self = Self {
        block_index_width: 4,
        block_size_shift: 12,
        compressed_block_size_shift: 15,
        compress: true,
        encrypt: false,
    };
}

impl Default for PackerConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ────────────────────────────────────────────────────────────
// INI persistence (Win32 Private Profile APIs)
// ────────────────────────────────────────────────────────────

unsafe extern "system" {
    fn GetPrivateProfileIntW(
        lpAppName: *const u16,
        lpKeyName: *const u16,
        nDefault: i32,
        lpFileName: *const u16,
    ) -> u32;
    fn WritePrivateProfileStringW(
        lpAppName: *const u16,
        lpKeyName: *const u16,
        lpString: *const u16,
        lpFileName: *const u16,
    ) -> i32;
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn get_ini_int(section: &[u16], key: &str, default: i32, file: &[u16]) -> i32 {
    let k = to_wide(key);
    let val = unsafe { GetPrivateProfileIntW(section.as_ptr(), k.as_ptr(), default, file.as_ptr()) };
    val as i32
}

const SECTION: &str = "yak_tc";

impl PackerConfig {
    pub fn load(ini_path: &str) -> Self {
        let file = to_wide(ini_path);
        let section = to_wide(SECTION);
        let def = Self::DEFAULT;

        Self {
            block_index_width: get_ini_int(&section, "block_index_width", def.block_index_width as i32, &file) as u8,
            block_size_shift: get_ini_int(&section, "block_size_shift", def.block_size_shift as i32, &file) as u8,
            compressed_block_size_shift: get_ini_int(&section, "compressed_block_size_shift", def.compressed_block_size_shift as i32, &file) as u8,
            compress: get_ini_int(&section, "compress", def.compress as i32, &file) != 0,
            encrypt: get_ini_int(&section, "encrypt", def.encrypt as i32, &file) != 0,
        }
    }

    pub fn save(&self, ini_path: &str) {
        let file = to_wide(ini_path);
        let section = to_wide(SECTION);

        let put = |key: &str, val: &str| {
            let k = to_wide(key);
            let v = to_wide(val);
            unsafe {
                WritePrivateProfileStringW(section.as_ptr(), k.as_ptr(), v.as_ptr(), file.as_ptr())
            };
        };

        put("block_index_width", &self.block_index_width.to_string());
        put("block_size_shift", &self.block_size_shift.to_string());
        put("compressed_block_size_shift", &self.compressed_block_size_shift.to_string());
        put("compress", if self.compress { "1" } else { "0" });
        put("encrypt", if self.encrypt { "1" } else { "0" });
    }
}

// ────────────────────────────────────────────────────────────
// Dialog
// ────────────────────────────────────────────────────────────

// Control IDs
const IDC_BLOCK_INDEX: i32 = 101;
const IDC_BLOCK_SIZE: i32 = 102;
const IDC_COMP_BLOCK: i32 = 103;
const IDC_COMPRESS: i32 = 104;
const IDC_ENCRYPT: i32 = 105;
const ID_OK: u16 = 1;
const ID_CANCEL: u16 = 2;

// Block index width options
const INDEX_OPTIONS: &[(u8, &str)] = &[(2, "2 bytes"), (4, "4 bytes"), (8, "8 bytes")];

// Block size options (shift -> human-readable)
const BLOCK_SIZE_OPTIONS: &[(u8, &str)] = &[
    (10, "1 KB"),
    (11, "2 KB"),
    (12, "4 KB"),
    (13, "8 KB"),
    (14, "16 KB"),
    (15, "32 KB"),
    (16, "64 KB"),
];

// Compressed block size options
const COMP_BLOCK_OPTIONS: &[(u8, &str)] = &[
    (12, "4 KB"),
    (13, "8 KB"),
    (14, "16 KB"),
    (15, "32 KB"),
    (16, "64 KB"),
    (17, "128 KB"),
    (18, "256 KB"),
    (19, "512 KB"),
    (20, "1 MB"),
];

/// Data passed to the dialog proc via LPARAM / GWLP_USERDATA.
struct DialogData {
    config: PackerConfig,
    ini_path: String,
}

// ── Dialog template builder ─────────────────────────────────

/// Build an in-memory DLGTEMPLATE as a u16 buffer.
fn build_dialog_template() -> Vec<u16> {
    let mut buf: Vec<u16> = Vec::with_capacity(512);

    // --- DLGTEMPLATE header ---
    let style: u32 = (WS_POPUP | WS_CAPTION | WS_SYSMENU).0
        | DS_MODALFRAME as u32
        | DS_SETFONT as u32;
    buf.push(style as u16);
    buf.push((style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(10); // cdit = number of controls
    buf.push(0); buf.push(0); // x, y
    buf.push(220); buf.push(145); // cx, cy

    buf.push(0); // menu: none
    buf.push(0); // class: default
    push_str(&mut buf, "Yak Packer Configuration"); // title
    buf.push(8); // font point size
    push_str(&mut buf, "MS Shell Dlg"); // font name

    // --- Controls ---
    let y0: i16 = 10;
    let rh: i16 = 16;
    let lx: i16 = 10;
    let cx: i16 = 110;
    let cw: i16 = 100;

    // Row 0: Block index width
    push_label(&mut buf, lx, y0, 95, 10, "Block index width:");
    push_combobox(&mut buf, cx, y0 - 2, cw, 80, IDC_BLOCK_INDEX as u16);

    // Row 1: Block size
    let y = y0 + rh;
    push_label(&mut buf, lx, y, 95, 10, "Block size:");
    push_combobox(&mut buf, cx, y - 2, cw, 80, IDC_BLOCK_SIZE as u16);

    // Row 2: Compressed block size
    let y = y0 + rh * 2;
    push_label(&mut buf, lx, y, 95, 10, "Compressed block size:");
    push_combobox(&mut buf, cx, y - 2, cw, 80, IDC_COMP_BLOCK as u16);

    // Row 3: Compress checkbox
    let y = y0 + rh * 3 + 6;
    push_checkbox(&mut buf, lx, y, 200, 12, IDC_COMPRESS as u16, "Compress streams");

    // Row 4: Encrypt checkbox
    let y = y0 + rh * 4 + 6;
    push_checkbox(&mut buf, lx, y, 200, 12, IDC_ENCRYPT as u16, "Encrypt");

    // Buttons
    let by: i16 = 120;
    push_button(&mut buf, 105, by, 50, 14, ID_OK, "OK", true);
    push_button(&mut buf, 160, by, 50, 14, ID_CANCEL, "Cancel", false);

    buf
}

fn align_dword(buf: &mut Vec<u16>) {
    if buf.len() % 2 != 0 {
        buf.push(0);
    }
}

fn push_str(buf: &mut Vec<u16>, s: &str) {
    buf.extend(s.encode_utf16());
    buf.push(0);
}

fn push_item_header(buf: &mut Vec<u16>, style: u32, x: i16, y: i16, cx: i16, cy: i16, id: u16) {
    align_dword(buf);
    buf.push(style as u16);
    buf.push((style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(x as u16);
    buf.push(y as u16);
    buf.push(cx as u16);
    buf.push(cy as u16);
    buf.push(id);
}

const SS_LEFT: u32 = 0x0000;

fn push_label(buf: &mut Vec<u16>, x: i16, y: i16, cx: i16, cy: i16, text: &str) {
    let style = (WS_CHILD | WS_VISIBLE).0 | SS_LEFT;
    push_item_header(buf, style, x, y, cx, cy, 0xFFFF);
    buf.push(0xFFFF); buf.push(0x0082); // class: STATIC
    push_str(buf, text);
    buf.push(0); // extra data
}

fn push_combobox(buf: &mut Vec<u16>, x: i16, y: i16, cx: i16, cy: i16, id: u16) {
    let style = (WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL).0
        | CBS_DROPDOWNLIST as u32;
    push_item_header(buf, style, x, y, cx, cy, id);
    buf.push(0xFFFF); buf.push(0x0085); // class: COMBOBOX
    buf.push(0); // title: empty
    buf.push(0); // extra data
}

fn push_checkbox(buf: &mut Vec<u16>, x: i16, y: i16, cx: i16, cy: i16, id: u16, text: &str) {
    let style = (WS_CHILD | WS_VISIBLE | WS_TABSTOP).0
        | BS_AUTOCHECKBOX as u32;
    push_item_header(buf, style, x, y, cx, cy, id);
    buf.push(0xFFFF); buf.push(0x0080); // class: BUTTON
    push_str(buf, text);
    buf.push(0); // extra data
}

fn push_button(buf: &mut Vec<u16>, x: i16, y: i16, cx: i16, cy: i16, id: u16, text: &str, default: bool) {
    let bs = if default { BS_DEFPUSHBUTTON } else { BS_PUSHBUTTON };
    let style = (WS_CHILD | WS_VISIBLE | WS_TABSTOP).0 | bs as u32;
    push_item_header(buf, style, x, y, cx, cy, id);
    buf.push(0xFFFF); buf.push(0x0080); // class: BUTTON
    push_str(buf, text);
    buf.push(0); // extra data
}

// ── Dialog helpers ──────────────────────────────────────────

fn populate_combo(dlg: HWND, id: i32, options: &[(u8, &str)], current: u8) {
    let combo = unsafe { GetDlgItem(Some(dlg), id) }.unwrap_or_default();
    let mut sel: usize = 0;
    for (i, (val, label)) in options.iter().enumerate() {
        let wide = to_wide(label);
        unsafe { SendMessageW(combo, CB_ADDSTRING, None, Some(LPARAM(wide.as_ptr() as isize))) };
        if *val == current {
            sel = i;
        }
    }
    unsafe { SendMessageW(combo, CB_SETCURSEL, Some(WPARAM(sel)), None) };
}

fn combo_value(dlg: HWND, id: i32, options: &[(u8, &str)]) -> u8 {
    let combo = unsafe { GetDlgItem(Some(dlg), id) }.unwrap_or_default();
    let idx = unsafe { SendMessageW(combo, CB_GETCURSEL, None, None) }.0 as usize;
    options.get(idx).map(|(v, _)| *v).unwrap_or(options[0].0)
}

// ── Dialog procedure ────────────────────────────────────────

unsafe extern "system" fn dialog_proc(
    dlg: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            unsafe { SetWindowLongPtrW(dlg, GWLP_USERDATA, lparam.0) };
            let data = unsafe { &*(lparam.0 as *const DialogData) };
            let cfg = &data.config;

            populate_combo(dlg, IDC_BLOCK_INDEX, INDEX_OPTIONS, cfg.block_index_width);
            populate_combo(dlg, IDC_BLOCK_SIZE, BLOCK_SIZE_OPTIONS, cfg.block_size_shift);
            populate_combo(dlg, IDC_COMP_BLOCK, COMP_BLOCK_OPTIONS, cfg.compressed_block_size_shift);

            if cfg.compress {
                let _ = unsafe { CheckDlgButton(dlg, IDC_COMPRESS, BST_CHECKED) };
            }
            if cfg.encrypt {
                let _ = unsafe { CheckDlgButton(dlg, IDC_ENCRYPT, BST_CHECKED) };
            }

            // Center dialog on parent
            let parent = unsafe { GetParent(dlg) }.unwrap_or_default();
            if !parent.is_invalid() {
                let mut pr = unsafe { mem::zeroed() };
                let mut dr = unsafe { mem::zeroed() };
                if unsafe { GetWindowRect(parent, &mut pr) }.is_ok()
                    && unsafe { GetWindowRect(dlg, &mut dr) }.is_ok()
                {
                    let x = pr.left + ((pr.right - pr.left) - (dr.right - dr.left)) / 2;
                    let y = pr.top + ((pr.bottom - pr.top) - (dr.bottom - dr.top)) / 2;
                    let _ = unsafe {
                        SetWindowPos(dlg, None, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER)
                    };
                }
            }

            1 // TRUE: set default focus
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as u16;
            if id == ID_OK {
                let ptr = unsafe { GetWindowLongPtrW(dlg, GWLP_USERDATA) };
                if ptr != 0 {
                    let data = unsafe { &mut *(ptr as *mut DialogData) };
                    data.config.block_index_width = combo_value(dlg, IDC_BLOCK_INDEX, INDEX_OPTIONS);
                    data.config.block_size_shift = combo_value(dlg, IDC_BLOCK_SIZE, BLOCK_SIZE_OPTIONS);
                    data.config.compressed_block_size_shift = combo_value(dlg, IDC_COMP_BLOCK, COMP_BLOCK_OPTIONS);
                    data.config.compress = unsafe { IsDlgButtonChecked(dlg, IDC_COMPRESS) } == BST_CHECKED.0;
                    data.config.encrypt = unsafe { IsDlgButtonChecked(dlg, IDC_ENCRYPT) } == BST_CHECKED.0;
                    data.config.save(&data.ini_path);
                }
                let _ = unsafe { EndDialog(dlg, 1) };
                1
            } else if id == ID_CANCEL {
                let _ = unsafe { EndDialog(dlg, 0) };
                1
            } else {
                0
            }
        }
        WM_CLOSE => {
            let _ = unsafe { EndDialog(dlg, 0) };
            1
        }
        _ => 0,
    }
}

// ── Public entry point ──────────────────────────────────────

pub fn show_dialog(parent: HWND, ini_path: &str) -> Option<PackerConfig> {
    let template = build_dialog_template();

    let mut data = DialogData {
        config: PackerConfig::load(ini_path),
        ini_path: ini_path.to_string(),
    };

    let result = unsafe {
        DialogBoxIndirectParamW(
            None,
            template.as_ptr() as *const DLGTEMPLATE,
            Some(parent),
            Some(dialog_proc),
            LPARAM(&mut data as *mut DialogData as isize),
        )
    };

    if result == 1 { Some(data.config) } else { None }
}

// ────────────────────────────────────────────────────────────
// Password Dialog
// ────────────────────────────────────────────────────────────

const IDC_PASSWORD: i32 = 201;

struct PasswordData {
    password: Option<Vec<u8>>,
}

fn build_password_template() -> Vec<u16> {
    let mut buf: Vec<u16> = Vec::with_capacity(256);

    let style: u32 = (WS_POPUP | WS_CAPTION | WS_SYSMENU).0
        | DS_MODALFRAME as u32
        | DS_SETFONT as u32;
    buf.push(style as u16);
    buf.push((style >> 16) as u16);
    buf.push(0); buf.push(0); // dwExtendedStyle
    buf.push(4); // cdit = 4 controls: label, edit, OK, Cancel
    buf.push(0); buf.push(0); // x, y
    buf.push(200); buf.push(65); // cx, cy
    buf.push(0); // menu
    buf.push(0); // class
    push_str(&mut buf, "Enter Password");
    buf.push(8); // font size
    push_str(&mut buf, "MS Shell Dlg");

    // Label
    push_label(&mut buf, 10, 10, 180, 10, "Password:");

    // Password edit box (ES_PASSWORD | ES_AUTOHSCROLL)
    const ES_PASSWORD: u32 = 0x0020;
    const ES_AUTOHSCROLL: u32 = 0x0080;
    let style = (WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER).0
        | ES_PASSWORD | ES_AUTOHSCROLL;
    push_item_header(&mut buf, style, 10, 22, 180, 14, IDC_PASSWORD as u16);
    buf.push(0xFFFF); buf.push(0x0081); // class: EDIT
    buf.push(0); // title: empty
    buf.push(0); // extra data

    // Buttons
    push_button(&mut buf, 85, 44, 50, 14, ID_OK, "OK", true);
    push_button(&mut buf, 140, 44, 50, 14, ID_CANCEL, "Cancel", false);

    buf
}

unsafe extern "system" fn password_proc(
    dlg: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    match msg {
        WM_INITDIALOG => {
            unsafe { SetWindowLongPtrW(dlg, GWLP_USERDATA, lparam.0) };

            // Center on parent
            let parent = unsafe { GetParent(dlg) }.unwrap_or_default();
            if !parent.is_invalid() {
                let mut pr = unsafe { mem::zeroed() };
                let mut dr = unsafe { mem::zeroed() };
                if unsafe { GetWindowRect(parent, &mut pr) }.is_ok()
                    && unsafe { GetWindowRect(dlg, &mut dr) }.is_ok()
                {
                    let x = pr.left + ((pr.right - pr.left) - (dr.right - dr.left)) / 2;
                    let y = pr.top + ((pr.bottom - pr.top) - (dr.bottom - dr.top)) / 2;
                    let _ = unsafe {
                        SetWindowPos(dlg, None, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER)
                    };
                }
            }

            1 // TRUE: let Windows set default focus
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as u16;
            if id == ID_OK {
                let ptr = unsafe { GetWindowLongPtrW(dlg, GWLP_USERDATA) };
                if ptr != 0 {
                    let data = unsafe { &mut *(ptr as *mut PasswordData) };
                    // Get text from edit control
                    let edit = unsafe { GetDlgItem(Some(dlg), IDC_PASSWORD) }.unwrap_or_default();
                    let len = unsafe { GetWindowTextLengthW(edit) } as usize;
                    if len > 0 {
                        let mut wbuf = vec![0u16; len + 1];
                        let got = unsafe { GetWindowTextW(edit, &mut wbuf) } as usize;
                        // Convert UTF-16 to UTF-8 bytes
                        let text: String = String::from_utf16_lossy(&wbuf[..got]);
                        data.password = Some(text.into_bytes());
                    }
                }
                let _ = unsafe { EndDialog(dlg, 1) };
                1
            } else if id == ID_CANCEL {
                let _ = unsafe { EndDialog(dlg, 0) };
                1
            } else {
                0
            }
        }
        WM_CLOSE => {
            let _ = unsafe { EndDialog(dlg, 0) };
            1
        }
        _ => 0,
    }
}

pub fn show_password_dialog(parent: HWND) -> Option<Vec<u8>> {
    let template = build_password_template();

    let mut data = PasswordData { password: None };

    let result = unsafe {
        DialogBoxIndirectParamW(
            None,
            template.as_ptr() as *const DLGTEMPLATE,
            Some(parent),
            Some(password_proc),
            LPARAM(&mut data as *mut PasswordData as isize),
        )
    };

    if result == 1 { data.password } else { None }
}
