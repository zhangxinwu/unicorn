while true
do
cd /data/local/tmp
chmod +x a.out
./gdbserver :12650 a.out
done