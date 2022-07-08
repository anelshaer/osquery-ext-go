# OSquery Extensions using Golang

Extending OSquery power by building extensions using Golang

## Description

OSquery have a ton of tables that can be used to query the system. but there are still a room to expand its capabilities by building extensions.

## ClamAV Extension
### Expected Output

OSquery interacting with ClamAV to scan files.

![ClamAV Extension output](https://github.com/anelshaer/osquery-ext-go/blob/main/screenshots/clamav_output.png?raw=true)

### Development

1. Clone this repository
```bash
git clone https://github.com/anelshaer/osquery-ext-go.git
cd clamav_scan/
```

2. Run the code directly
```bash
go run ./main.go --socket /Users/$USER/.osquery/shell.em

```

3. Use osquery with Extension enabled
```bash
osqueryi --nodisable_extensions
```

### Build

1. Build for linux
```bash
env GOOS=linux GOARCH=amd64 go build -o clamav_scan
```
2. Run OSquery with the new Extension
```bash
osqueryi --extension clamav_scan
```

### Usage

This Extension was built with non fixed clamav socket to support different deployments of clamav.

Requirements:
1. Clamav Socket
2. File Path to be scanned

Examples:

1. scan a single file

```bash
select status, result, path from clamav_scan where socket='/var/run/clamav/clamd.ctl' AND path = '/tmp/clamav/eicar.com';
```

2. scan a directory or muliple files

```bash
select status, result, path from clamav_scan where socket='/var/run/clamav/clamd.ctl' AND path in (select path from file where path like '/tmp/clamav/eicar%' OR path like '/bin/lz%');
```

### Dependencies

* Clamav - should be installed and having a socket

### Installing

Install ClamAV and configure it to confirm it have a socket file

```bash
sudo apt install clamav clamav-daemon
sudo dpkg-reconfigure clamav-daemon
```

## Help / contribution

Please file an issue on GitHub or contact me directly.

## Authors

[@Ahmed Elshaer](https://www.linkedin.com/in/anelshaer)

## Version History

* 0.1
    * Initial Release

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

