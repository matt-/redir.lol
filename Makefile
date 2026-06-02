.PHONY: build build-linux run run-root pf-redirect iptables-redirect clean

LDFLAGS := -ldflags="-s -w"

build:
	go build $(LDFLAGS) -o redir .

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o redir-linux .

run:
	go run . -port 8080 -dns-port 5300

run-root: build
	sudo ./redir -port 80 -dns-port 53

# macOS: redirect port 53 -> dns-port without running as root
pf-redirect:
	echo "rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port 5300" | sudo pfctl -ef -

# Linux: redirect port 53 -> dns-port without running as root
iptables-redirect:
	sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5300
	sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300

clean:
	rm -f redir redir-linux
