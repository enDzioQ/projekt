# nftctl

Prosty bashowy panel tekstowy do zarządzania dedykowaną tabelą nftables.

## Funkcje

- blacklist IP dla IPv4 i IPv6
- whitelist portów TCP i UDP
- tryb `monitor` i `strict`
- menu konsolowe oraz komendy CLI
- automatyczny backup bieżącej tabeli przed zastosowaniem zmian

## Uruchomienie

```bash
chmod +x nftctl.sh
sudo ./nftctl.sh menu
```

## Przykłady CLI

```bash
sudo ./nftctl.sh add-ip 203.0.113.10
sudo ./nftctl.sh add-port tcp 22
sudo ./nftctl.sh add-port both 53
sudo ./nftctl.sh mode strict
sudo ./nftctl.sh status
```

## Uwaga

Skrypt zarządza tylko własną tabelą `inet nftctl`, więc nie nadpisuje całego rulesetu systemowego.
Tryb `monitor` zostawia ruch poza whitelistą przepuszczany, a `strict` ustawia policy drop na wejściu.
