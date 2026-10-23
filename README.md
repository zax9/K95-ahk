# K95-ahk

Use the original Corsair K95 RGB's **G1-G18 keys** with AutoHotkey v2 while iCUE and its services are stopped.

**This repo and its contents brought to you by GPT-6 Astra.**

The code and documentation were created with AI assistance. The hardware test results came from tests on the owner's keyboard. See [Test status](#test-status) for the checks completed and the limits of those checks.

## Supported keyboard

This project targets the **original K95 RGB with 18 G keys**:

| Item | Value |
| --- | --- |
| USB vendor ID | `1B1C` |
| USB product ID | `1B11` |
| G-key input collection | `COL03` |
| Observed interface | `MI_00`; the decoder also accepts other interface numbers |
| HID usage page / usage | `FFC0` / `0002` |
| Input report | 64 bytes, report ID `03` |
| Hardware test system | Windows 10 x64, build 19045 |

Other K95 models, including models with six G keys, are not covered by the hardware tests.

The AutoHotkey script receives Windows Raw Input reports directly. It does not use the iCUE SDK or run the diagnostic program as a helper.

## Files

| Path | Purpose |
| --- | --- |
| [`K95_GKeys_v0_1.ahk`](K95_GKeys_v0_1.ahk) | AutoHotkey v2 script with the configured key actions |
| [`diagnostic/K95Diagnostic_v0_2.exe`](diagnostic/K95Diagnostic_v0_2.exe) | Portable Windows x64 diagnostic program |
| [`diagnostic/source/`](diagnostic/source/) | C++ source, decoder, and decoder tests |
| [`diagnostic/build.cmd`](diagnostic/build.cmd) | Windows build script |
| [`diagnostic/README.txt`](diagnostic/README.txt) | Detailed diagnostic instructions |
| [`diagnostic/CHANGES.txt`](diagnostic/CHANGES.txt) | Diagnostic v0.2 changes |
| [`diagnostic/VALIDATION.txt`](diagnostic/VALIDATION.txt) | Original build and validation record |
| [`diagnostic/REFERENCES.txt`](diagnostic/REFERENCES.txt) | Protocol sources and Windows API references |
| [`diagnostic/SHA256SUMS.txt`](diagnostic/SHA256SUMS.txt) | Checksums for the diagnostic package |
| [`diagnostic/third_party/`](diagnostic/third_party/) | Compiler runtime notices |

## Run the AutoHotkey script

1. Install [AutoHotkey v2](https://www.autohotkey.com/). AutoHotkey v1 cannot run this script.
2. Download this repository with **Code > Download ZIP**, then extract it.
3. Close iCUE and stop its services. Close the diagnostic if it is open.
4. Check the program paths and sound device names in the table below.
5. Run `K95_GKeys_v0_1.ahk` with AutoHotkey v2.

The script stays in the system tray. It does not show a main window. To stop it, right-click its tray icon and select **Exit**.

The script does not stop iCUE services or add itself to Windows startup. Keep it as a separate script if another script also registers Raw Input for this HID usage.

### Assigned actions

Each action runs **once when the G key is pressed**. Holding a key does not repeat its action. Each shortcut sends a complete press and release to the active application.

| G key | Action |
| --- | --- |
| G1 | Run `C:\utils\bedtime.bat` |
| G9 | Send `Ctrl+Alt+Right` |
| G10 | Run `C:\utils\nircmd.exe setdefaultsounddevice "Headphones"` |
| G11 | Run `C:\utils\nircmd.exe setdefaultsounddevice "Speakers"` |
| G13 | Send `Ctrl+Shift+Tab` |
| G14 | Send `Ctrl+Tab` |
| G17 | Send `Ctrl+F4` |
| G18 | Send `F5` |

The other G keys have no assigned action. The batch file and NirCmd executable are not included. The three Run actions use `C:\utils` as their working directory. The sound device names must match the names on the PC.

### Change the actions

Edit the two functions near the top of `K95_GKeys_v0_1.ahk`:

- `K95_OnPress(key)` receives each key press. `key` is an integer from 1 through 18. Add or change a `case` in its `switch` block.
- `K95_OnRelease(key, reason)` receives each key release. No release actions are assigned in v0.1.

The release reason is `"release"`, `"disconnect"`, or `"exit"`. If a device disconnects or the script exits, the script calls the release handler for each key still marked as held.

For example, add `case 2: SendInput("^c")` to the press handler to make G2 send Ctrl+C. Save your changes, then select **Reload Script** from the tray menu.

Keep handlers short. Use `Run` for programs that continue in the background. A failed action shows a tray notification; the listener stays active.

## Run the diagnostic

The diagnostic checks whether Windows receives press and release reports for all 18 G keys. It does not run the AutoHotkey actions.

1. Stop the AutoHotkey script. Keep iCUE and its services stopped.
2. Run `diagnostic\K95Diagnostic_v0_2.exe`.
3. Read the background check. If it lists an active Corsair process or service, stop that component and select **Rescan**.
4. Select **Start test**.
5. Press and release an ordinary key once. Then press and release G1 through G18, one at a time.
6. Select **Stop test**. The test also stops after 120 seconds.
7. Select **Save report**. Close and reopen the program to run another test.

A complete result is **18 / 18**, with a press and a later release for each key. Raw HID and Direct HID can both observe the same event; their report counts are not counts of separate physical presses.

The diagnostic reads device input and checks process and service names. It does not change keyboard settings, stop services, install drivers, or send data over the network. Report samples can contain ordinary keys pressed during the test. Do not type private text during capture. Review a report before you share it.

## Test status

| Check | Result |
| --- | --- |
| Diagnostic C++ build | Windows x64 binary compiled with MinGW-w64 GCC 13.2 |
| Diagnostic decoder tests | Passed with AddressSanitizer and UndefinedBehaviorSanitizer on Linux |
| Physical keyboard test | All 18 keys produced a press and release with iCUE and its services stopped |
| Disconnect and reconnect test | All 18 keys passed again after the diagnostic was closed and the keyboard was disconnected and reconnected; iCUE and its services remained stopped |
| AutoHotkey decoding logic | Compared against all 262,144 possible G-key masks; unrelated bits were excluded |
| AutoHotkey action mapping | All eight requested assignments checked |
| AutoHotkey execution on Windows | Not yet tested |

The hardware results were reported on **23 October 2026**. They show that the tested keyboard setup can provide G-key input after a reconnect without restarting iCUE.

The tests did not remove installed Corsair kernel drivers. They do not establish the same result on a clean Windows installation or with other firmware. The diagnostic checks named processes and active services; it cannot prove that every Corsair component is absent.

The diagnostic package is preserved as supplied. Its `README.txt` and `VALIDATION.txt` describe the state before the later hardware tests. The table above records those later results. The AutoHotkey logic checks do not replace a test of the script on Windows.

## Build the diagnostic

No compiler is needed to run the supplied executable.

To rebuild, use a 64-bit MinGW-w64 compiler on `PATH`, or open an **x64 Native Tools Command Prompt for Visual Studio**. From the repository root, run:

```bat
cd diagnostic
build.cmd
```

The build creates `K95Diagnostic_v0_2_rebuilt.exe`. It does not replace the supplied binary. The build script stops if that output file already exists.

To run the decoder tests with MinGW-w64 from the repository root:

```bat
g++ -std=c++17 -O2 -Wall -Wextra -Werror diagnostic\source\decoder_tests.cpp -o "%TEMP%\K95_decoder_tests.exe"
"%TEMP%\K95_decoder_tests.exe"
```

To check the supplied executable's SHA-256 hash from the repository root:

```bat
certutil -hashfile diagnostic\K95Diagnostic_v0_2.exe SHA256
```

Compare the result with its entry in `diagnostic\SHA256SUMS.txt`.

## Input format and references

The G-key state is a bit mask inside report `03`. Byte offsets below are zero-based and include the report ID at byte 0.

| Report location | Keys |
| --- | --- |
| Byte 16, bits 0-7 | G1-G8 |
| Byte 17, bits 0-1 | G9-G10 |
| Byte 18, bits 0-7 | G11-G18 |

The script compares each report with the prior state to find presses and releases. It processes all reports in each Windows input message. It runs the configured actions after the input callback returns.

Protocol references and source revisions are listed in [`diagnostic/REFERENCES.txt`](diagnostic/REFERENCES.txt). The implementation uses the [Windows Raw Input API](https://learn.microsoft.com/en-us/windows/win32/inputdev/about-raw-input) and AutoHotkey v2's [OnMessage](https://www.autohotkey.com/docs/v2/lib/OnMessage.htm) and [DllCall](https://www.autohotkey.com/docs/v2/lib/DllCall.htm) functions.
