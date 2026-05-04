# Gửi 1 request mỗi 1 giây
ip netns exec ns10 bash -c 'while true; do curl -s -o /dev/null http://10.10.2.2; sleep 1; done' 
