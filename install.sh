pkg upgrade -y
pkg install openssh -y
cd /data/data/com.termux/files/usr/etc/ssh/
rm sshd_config
wget https://raw.githubusercontent.com/bsviijrkvc/dns/refs/heads/main/sshd_config
