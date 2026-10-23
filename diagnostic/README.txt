K95 Diagnostic v0.2

PURPOSE

Check whether the original Corsair K95 RGB sends G1 through G18 input with
iCUE stopped. The USB hardware ID for this model is VID 1B1C, PID 1B11.
This program is for 64-bit Windows 10, including build 19045.

FIRST TEST

1. Extract the ZIP file to a folder.
2. Exit iCUE from its notification-area icon.
3. Run K95Diagnostic_v0_2.exe. No installation is required.
4. Read the background-check result at the top of the window.
   If Corsair components are still running, click Save report. The report
   lists the process and service names that the program found.
5. Stop the listed Corsair services in services.msc. Close the listed
   Corsair applications. Then click Rescan.
   The program does not stop or change services for you.
6. Click Start test.
7. Press and release A once. This checks the standard keyboard input.
   Then press and release G1, G2, and continue through G18.
   Hold each key for about half a second. Release it before the next key.
   The key cell should show DOWN, then DOWN + UP.
8. Click Stop test. The test also stops after 120 seconds.
9. Click Save report. Send the saved .txt file back in the chat.
   Attach the full saved file. The window does not show all device details.
   Save the report even if no G keys respond.

The program uses one capture per window. Close and reopen it for another
test. Reports use a new timestamp in the filename. Existing files are
not replaced.

If the process or service check is incomplete, the test cannot start.
Try running the program as administrator only if the report shows an
access error. Administrator rights are not requested at startup.

The executable is unsigned. Windows may show an unknown-publisher notice.
The source code and build instructions are included for inspection.

WHAT THE RESULTS MEAN

DOWN + UP: The program received a press and a later release for that key
in the supported Corsair input format, through at least one input method.

DOWN: The key is currently reported as held.

UP missing: A press was received, but no release was received before the
test stopped. A device disconnect is not counted as a key release.

waiting / NOT OBSERVED: The program has not decoded that G key. This is
not proof that direct access is impossible.

Raw HID and Direct HID: Counts of input reports from the K95. Both methods
may receive the same key event. The 18-key result counts unique key names.

Standard keys: Windows keyboard events from the K95. These show that the
standard keyboard interface is active. They do not prove G-key access.

Decoded: Reports that match the expected 64-byte report ID 03 on the
K95's COL03 input collection, on any interface number.

BACKGROUND CHECK

The program checks process names and active service names/display names
for Corsair, iCUE, and the old CUE.exe process. It checks before capture,
about every two seconds during capture, and at the end. If a matching
component is found during capture, the report marks the test as not clean.

These checks cannot prove that every possible Corsair component is absent.
For example, a component could use an unrelated name or run between checks.
Installed kernel drivers are not stopped or removed by this test.

IF NOTHING HAPPENS

Press and release an ordinary key once during the capture. Check whether
the Standard keys count increases. Then stop and save the report.

This version is passive. It does not enable Corsair's software input
mode. Independent driver code indicates that this mode can be required
before report 03 is sent. The log will help identify whether the next step
is mode initialization, another report format, or a Windows access issue.

For a separate test after power-on, stop iCUE and its services first.
Disconnect the keyboard's USB connections, reconnect them, then reopen
the diagnostic. Record in your reply whether you did this. A successful
test only after iCUE ran may depend on input mode left by iCUE.

The window now shows report counts when the test stops. It distinguishes
no HID data, an unsupported report format, and supported reports without
G-key presses.

Older firmware without report ID 03 is not automatically decoded. Its
sample reports can still be included in the log for analysis.

DATA AND SCOPE

Capture is active only between Start test and Stop test (or the timeout).
Payloads are accepted only from VID 1B1C / PID 1B11 device paths.
Metadata for other Corsair HID interfaces can appear in the report.

Report samples can contain ordinary keys pressed on the K95 during the
test. Do not type passwords or other private text during capture. Review
the report before sharing it. The program does not send data anywhere.

The report is written only when you use Save report. The log is bounded
to about two million text characters. Raw sample packets are limited to
24 per input method, interface, report ID, and report length. The first
two samples from each group also appear in the window. G-key transitions continue
to be tracked if this limit is reached.

The program uses Windows Raw Input and asynchronous HID reads. It does
not use the iCUE SDK, write device settings, install a driver, inject keys,
change the registry, create a startup entry, or terminate a process.
It does not yet connect the detected keys to AutoHotkey.

VALIDATION

The decoder tests cover all 18 keys, press/release pairs, simultaneous keys,
repeated reports, invalid report lengths, unrelated bits, and batch bounds.
See VALIDATION.txt for the checks completed for this package.

The actual K95 and Windows 10 build 19045 were not available in the build
environment. Detection on your keyboard must be confirmed with this test.
