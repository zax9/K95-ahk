#Requires AutoHotkey v2.0
#SingleInstance Force

; K95 G keys v0.1 -- original K95 RGB with 18 G keys (VID 1B1C / PID 1B11).
;
; START: Close the diagnostic. Keep iCUE and its services stopped.
; Run this file with AutoHotkey v2. The script stays in the system tray.
; STOP: Right-click this script's tray icon, then select Exit.
;
; Edit K95_OnPress() and K95_OnRelease() below to change the actions.
; Each handler receives a key number from 1 to 18.
; An action runs once per press. Holding a key does not repeat the action.
; Shortcuts go to the active application. Each SendInput sends a full tap.
; The other G keys and all release actions have no action assigned.
;
; This file uses Windows Raw Input. It does not use the iCUE SDK.
; It sends no device configuration commands and writes no log files.
; Keep this as a separate script if another script also registers Raw Input.

Persistent()
ListLines(false)
A_IconTip := "K95 G keys v0.1"

try {
    K95 := K95RawInput(K95_OnPress, K95_OnRelease)
} catch Error as err {
    MsgBox("Cannot start the K95 listener.`n`n" err.Message, "K95 G keys", "Iconx")
    ExitApp(1)
}

; ===================== EDIT YOUR ACTIONS HERE =====================

K95_OnPress(key) {
    switch key {
        case 1:  Run('"C:\utils\bedtime.bat"', "C:\utils")
        case 9:  SendInput("^!{Right}")
        case 10: Run('"C:\utils\nircmd.exe" setdefaultsounddevice "Headphones"', "C:\utils")
        case 11: Run('"C:\utils\nircmd.exe" setdefaultsounddevice "Speakers"', "C:\utils")
        case 13: SendInput("^+{Tab}")
        case 14: SendInput("^{Tab}")
        case 17: SendInput("^{F4}")
        case 18: SendInput("{F5}")
        ; Add cases for G2-G8, G12, G15, or G16 here.
    }
}

K95_OnRelease(key, reason) {
    ; key: 1 through 18.
    ; reason: "release", "disconnect", or "exit".
    ; A disconnect or exit also releases any key still marked as held.
    ; Add release actions here. No release actions are assigned in v0.1.
    return
}

; Keep action handlers short. Use Run, rather than RunWait, for programs.
; A handler error shows a tray notification. The listener stays active.

; ======================= RAW INPUT LISTENER =======================

class K95RawInput {
    __New(onPress, onRelease) {
        this.onPress := onPress
        this.onRelease := onRelease
        this.devices := Map()
        this.queue := []
        this.draining := false
        this.timerPending := false
        this.stopped := false
        this.headerSize := 8 + 2 * A_PtrSize
        this.inputFn := ObjBindMethod(this, "OnInput")
        this.changeFn := ObjBindMethod(this, "OnDeviceChange")
        this.drainFn := ObjBindMethod(this, "Drain")
        this.exitFn := ObjBindMethod(this, "Stop")

        ; RAWINPUTDEVICE: USHORT page, USHORT usage, DWORD flags, HWND.
        ; Confirmed by the diagnostic: usage page FFC0, usage 0002.
        rid := Buffer(8 + A_PtrSize, 0)
        NumPut("UShort", 0xFFC0, "UShort", 0x0002, rid, 0)
        NumPut("UInt", 0x2100, rid, 4) ; INPUTSINK | DEVNOTIFY
        NumPut("Ptr", A_ScriptHwnd, rid, 8)

        OnMessage(0x00FF, this.inputFn)  ; WM_INPUT
        OnMessage(0x00FE, this.changeFn) ; WM_INPUT_DEVICE_CHANGE
        if !DllCall("User32\RegisterRawInputDevices", "Ptr", rid,
            "UInt", 1, "UInt", rid.Size, "Int") {
            code := A_LastError
            OnMessage(0x00FF, this.inputFn, 0)
            OnMessage(0x00FE, this.changeFn, 0)
            throw Error("Raw Input registration failed. Windows error: " code)
        }
        OnExit(this.exitFn)
    }

    OnInput(wParam, lParam, msg, hwnd) {
        ; Keep WM_INPUT short. Run the actions later, from a timer.
        Critical(100)
        if this.stopped || hwnd != A_ScriptHwnd
            return

        size := 0
        result := DllCall("User32\GetRawInputData", "Ptr", lParam,
            "UInt", 0x10000003, "Ptr", 0, "UInt*", &size,
            "UInt", this.headerSize, "UInt")
        if result != 0 || size < this.headerSize + 8 || size > 1048576
            return

        packet := Buffer(size)
        copied := DllCall("User32\GetRawInputData", "Ptr", lParam,
            "UInt", 0x10000003, "Ptr", packet, "UInt*", &size,
            "UInt", this.headerSize, "UInt")
        if copied = 0xFFFFFFFF || copied < this.headerSize + 8 || copied > packet.Size
            return
        if NumGet(packet, 0, "UInt") != 2 ; RIM_TYPEHID
            return

        total := NumGet(packet, 4, "UInt")
        if total < this.headerSize + 8 || total > copied
            return
        device := NumGet(packet, 8, "Ptr")
        if !this.IsK95(device)
            return

        reportSize := NumGet(packet, this.headerSize, "UInt")
        count := NumGet(packet, this.headerSize + 4, "UInt")
        offset := this.headerSize + 8
        if reportSize != 64 || count = 0 || count > (total - offset) // 64
            return

        ; One Windows message can contain more than one HID report.
        Loop count {
            if NumGet(packet, offset, "UChar") = 0x03 {
                ; Offsets include the report ID at byte 0.
                ; Byte 17 bits 2-7 are NOT G keys.
                mask := NumGet(packet, offset + 16, "UChar")
                    | ((NumGet(packet, offset + 17, "UChar") & 3) << 8)
                    | (NumGet(packet, offset + 18, "UChar") << 10)
                this.Update(device, mask, "release")
            }
            offset += reportSize
        }
        ; Return no value so AutoHotkey can process WM_INPUT normally.
        ; Windows requires default processing for foreground input cleanup.
    }

    IsK95(device) {
        if this.devices.Has(device)
            return this.devices[device].target

        chars := 0
        result := DllCall("User32\GetRawInputDeviceInfoW", "Ptr", device,
            "UInt", 0x20000007, "Ptr", 0, "UInt*", &chars, "UInt")
        if result != 0 || chars = 0 || chars > 32768
            return false ; Do not cache a failed query; retry on the next report.

        name := Buffer((chars + 1) * 2, 0)
        result := DllCall("User32\GetRawInputDeviceInfoW", "Ptr", device,
            "UInt", 0x20000007, "Ptr", name, "UInt*", &chars, "UInt")
        if result = 0xFFFFFFFF
            return false
        path := StrGet(name, "UTF-16")
        target := RegExMatch(path, "i)(?:^|[&#])vid_1b1c(?=[&#]|$)")
            && RegExMatch(path, "i)(?:^|[&#])pid_1b11(?=[&#]|$)")
            && RegExMatch(path, "i)(?:^|[&#])col03(?=[&#]|$)")
        ; Do not require MI_01. This keyboard uses MI_00 / COL03.
        this.devices[device] := {target: !!target, held: 0}
        return target
    }

    Update(device, next, reason) {
        state := this.devices[device]
        changed := state.held ^ next
        state.held := next
        if !changed
            return
        Loop 18 {
            bit := 1 << (A_Index - 1)
            if changed & bit
                this.queue.Push([A_Index, !!(next & bit), reason])
        }
        this.Schedule()
    }

    Schedule() {
        if !this.stopped && !this.draining && !this.timerPending && this.queue.Length {
            this.timerPending := true
            SetTimer(this.drainFn, -1)
        }
    }

    Drain() {
        this.draining := true
        this.timerPending := false
        try {
            while !this.stopped && this.queue.Length {
                event := this.queue.RemoveAt(1)
                try {
                    if event[2]
                        this.onPress.Call(event[1])
                    else
                        this.onRelease.Call(event[1], event[3])
                } catch Error as err {
                    TrayTip("G" event[1] ": " err.Message, "K95 action failed", 3)
                }
            }
        } finally {
            this.draining := false
            this.Schedule()
        }
    }

    OnDeviceChange(wParam, lParam, msg, hwnd) {
        Critical(100)
        if this.stopped || hwnd != A_ScriptHwnd
            return
        if (wParam = 1 || wParam = 2) && this.devices.Has(lParam) {
            if this.devices[lParam].target
                this.Update(lParam, 0, "disconnect")
            this.devices.Delete(lParam)
        }
        ; A new handle is checked on its first input report.
    }

    Stop(*) {
        if this.stopped
            return
        this.stopped := true
        SetTimer(this.drainFn, 0)
        this.queue := [] ; Do not start queued actions during exit.
        OnMessage(0x00FF, this.inputFn, 0)
        OnMessage(0x00FE, this.changeFn, 0)

        rid := Buffer(8 + A_PtrSize, 0)
        NumPut("UShort", 0xFFC0, "UShort", 0x0002, rid, 0)
        NumPut("UInt", 1, rid, 4) ; RIDEV_REMOVE; HWND must be zero.
        DllCall("User32\RegisterRawInputDevices", "Ptr", rid,
            "UInt", 1, "UInt", rid.Size, "Int")

        for device, state in this.devices {
            if !state.target
                continue
            Loop 18 {
                if state.held & (1 << (A_Index - 1)) {
                    try this.onRelease.Call(A_Index, "exit")
                }
            }
        }
        this.devices.Clear()
    }
}

; REFERENCES / VALIDATION
; Report layout: K95 Diagnostic v0.2 and the successful reconnect capture.
; Windows API: https://learn.microsoft.com/en-us/windows/win32/inputdev/raw-input
; AHK v2 API: https://www.autohotkey.com/docs/v2/lib/OnMessage.htm
; https://www.autohotkey.com/docs/v2/lib/DllCall.htm
; https://www.autohotkey.com/docs/v2/lib/Run.htm
; https://www.autohotkey.com/docs/v2/lib/Send.htm
; The diagnostic verified the hardware reports. This AHK script still needs
; a Windows runtime test; it was not run on the keyboard during development.
