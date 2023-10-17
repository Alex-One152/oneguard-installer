# OneGuard installer

**Этот проект представляет собой скрипт bash, целью которого является максимально простая настройка VPN [WireGuard](https://www.wireguard.com/) на сервере Linux.!**

WireGuard — это двухточечная VPN, которую можно использовать по-разному. Здесь мы имеем в виду VPN: клиент перенаправляет весь свой трафик через зашифрованный туннель на сервер.
Сервер будет применять NAT к трафику клиента, поэтому будет выглядеть так, как будто клиент просматривает Интернет с IP-адресом сервера.

Скрипт поддерживает как IPv4, так и IPv6

WireGuard не подходит для вашей среды? Проверьте [openvpn-install](https://github.com/angristan/openvpn-install).

## Требования
Поддерживаемые дистрибутивы:
- AlmaLinux >= 8
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
- Rocky Linux >= 8
- Ubuntu >= 18.04

## Использование

Загрузите и выполните скрипт. Ответьте на вопросы, заданные скриптом, а он позаботится обо всем остальном.

```bash
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

Он установит WireGuard (модуль ядра и инструменты) на сервер, настроит его, создаст службу systemd и файл конфигурации клиента.

Запустите скрипт еще раз, чтобы добавить или удалить клиентов!

## Скажи спасибо

Если у вас есть желание то вы можете [Поддержать автора](https://www.donationalerts.com/r/alex_one152)