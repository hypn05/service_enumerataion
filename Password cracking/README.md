# Password Cracking


- MD5 32 hex characters.
- SHA-1 40 hex characters.
- SHA-256 64 hex characters.
- SHA-512 128 hex characters.
- Find the type of hash:
  - > hash-identifier

- Find hash type at [Hashkiller](https://hashkiller.co.uk)
- Running john will tell you the hash type even if you don't want to crack it:
  - > john hashes.txt

- Paste the entire /etc/shadow in file and run
  - > john hashes.txt

- GPU cracking:
  - > hashcat -m 500 -a 0 -o output.txt -remove hashes.txt /usr/share/wordlists/rockyou.txt

- CPU cracking:
  - > john --wordlist=/usr/share/wordlists/rockyou.txt 127.0.0.1.pwdump

- Cracking */etc/shadow*:
  - > unshadow /etc/passwd /etc/shadow /tmp/combined; john --wordlist=rockyou.txt /tmp/combined

- Generating wordlists
  - > crunch 6 6 0123456789ABCDEF 5o crunch1.txt

-Online rainbow tables:

- [Crackstation](https://crackstation.net/)
- [CMD5](http://www.cmd5.org/)
- [Crackhash](http://crackhash.com/)
- [HashKiller](https://hashkiller.co.uk/md5-decrypter.aspx)
- [OnlinehashCrack](https://www.onlinehashcrack.com/)
- [RainBowTable](http://rainbowtables.it64.com/)
- [md5online](http://www.md5online.org/)
