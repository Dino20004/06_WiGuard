# WiGuard Examples & Sample Output

Here are examples of how CLI output is presented using rich layout tables.

## wiguard scan Output Example
```
┌────────────────────────────────────────────────────────────────────────┐
│                          Nearby WiFi Networks                          │
├───────────────────┬───────────────────┬─────────┬────────────┬─────────┤
│ SSID              │ BSSID             │ Signal  │ Encryption │ Risk    │
├───────────────────┼───────────────────┼─────────┼────────────┼─────────┤
│ OfficeNet         │ 00:14:22:01:23:45 │ -45 dBm │ WPA3       │ SAFE    │
│ OfficeNet         │ 00:14:22:99:99:99 │ -20 dBm │ Open       │ CRITICAL│
│ GuestWiFi         │ 10:C3:7B:A2:3B:11 │ -65 dBm │ WPA2       │ SAFE    │
└───────────────────┴───────────────────┴─────────┴────────────┴─────────┘
```

In the output above, a duplicate SSID is detected with differing security settings (WPA3 vs Open) and an anomalous signal strength (-20 dBm is extremely loud, suggesting an attacker nearby), yielding a **CRITICAL** risk score.
