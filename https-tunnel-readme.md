## vscode debug

```bash
cp .vscode/launch_example.json .vscode/launch.json
```

then modify the arguements in launch.json, especially the `-k` and `-s`.

## install

```bash
make gh
# eg cargo install --path . --bin sslocal --features https-tunnel
```

## run.vbs

useful for windows users

```bash
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "taskkill /F /IM sslocal.exe", 0, True
WshShell.Run "sslocal --local-addr 0.0.0.0:2080 -k username:password -v -m aes-256-gcm -s host:444", 0
```
