cargo build -r --bin ssserver --target x86_64-unknown-linux-gnu --target-dir build/release
podman build . -f Dockerfile.dyn -t quay.io/arloor/app:ssserver --network host
podman login quay.io  
podman push quay.io/arloor/app:ssserver

for host in us.arloor.dev; do
    ssh root@$host '
        . pass
        hostname;
        systemctl restart ss;
        podman rmi -a 2>/dev/null
    '
done



