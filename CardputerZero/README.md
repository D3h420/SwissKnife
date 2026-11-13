# SwissKnife dla Cardputer Zero

**LAB5 / D3h420** · aplikacja 320 × 170 dla Raspberry Pi OS i APPLaunch.

## Stan implementacji

To niezależny interfejs do istniejącego SwissKnife. Kod modułów pozostaje w `../modules/`, a wspólne API, katalog funkcji, wykrywanie sprzętu i ścieżki danych w `../core/`. Aplikacja nie zawiera kopii modułów. GUI uruchamia się jako zwykły użytkownik. Dotychczasowe `swiss_knife.py` i `RPi_LCD_HAT/` nadal działają swoimi dotychczasowymi ścieżkami.

Kod działa w trybie symulacji na komputerze. **Nie został sprawdzony na fizycznym Cardputer Zero**. Status „wymaga testów na urządzeniu” oznacza zaimplementowaną ścieżkę kodu, a nie potwierdzoną zgodność sprzętową.

## Podstawa platformowa

- [M5Stack opis sprzętu](https://docs.m5stack.com/en/CardputerZero): CM0, ARM64, 512 MB RAM, LCD ST7789V 320 × 170, klawiatura matrycowa, USB-A i USB-C.
- [M5Stack obsługa klawiatury](https://docs.m5stack.com/en/compute/cardputerzero/usage): `fn+F/X/Z/C` daje kierunki; Enter potwierdza, Esc wraca, przytrzymany Esc opuszcza aplikację.
- [CardputerZero/launcher](https://github.com/CardputerZero/launcher): APPLaunch używa LVGL, framebuffer i wejścia evdev; zewnętrzne aplikacje są wykrywane przez wpisy `.desktop`.
- [AppBuilder Python FrameBuffer HelloWorld](https://github.com/CardputerZero/AppBuilder/tree/main/examples/Python_FrameBuffer_HelloWorld): oficjalny przykład Pythona korzysta z Pillow, `/dev/fb0` RGB565 i python-evdev.
- [AppBuilder pack-deb.sh](https://github.com/CardputerZero/AppBuilder/blob/main/scripts/pack-deb.sh): format pakowania `.deb`, `packaging/meta.env`, `build.sh`, `stage.sh`, ikona i wpis APPLaunch.

Oficjalny szablon preferuje LVGL w C/C++. W tym projekcie Python bezpośrednio wywołuje moduły SwissKnife, więc warstwa GUI w C wymagałaby dodatkowego protokołu i osobnego procesu dla każdego widoku. Używamy oficjalnie pokazanego wariantu Python + Pillow + framebuffer. Odświeżamy tylko przy zmianie stanu lub raz na sekundę, bez animacji wymagających wysokiej liczby klatek. Na urządzeniu trzeba potwierdzić wydajność i dostęp do wejścia/ekranu.

## Architektura

```text
swiss_knife.py ─┐
RPi_LCD_HAT/ ────┼── core/features.py + modules/ + core/paths.py
CardputerZero/ ─┘                     │
              └── core/engine.py + core/hardware.py
```

`core/engine.py` udostępnia listę modułów, status zależności i sprzętu, konfigurację, zdarzenia wyniku, postęp, błąd i anulowanie. Operacje pracują w wątku roboczym; GUI czyta kolejkę zdarzeń bez blokowania pętli rysowania. `core/hardware.py` wykrywa interfejsy, USB, GPS, trasę domyślną, narzędzia i uprawnienia. Warstwa Cardputer zawiera tylko ekran, klawiaturę i nawigację.

Zależności kodu są pobierane **podczas każdego budowania pakietu** z aktualnych katalogów `core/`, `modules/`, `html/` i `swiss_knife.py` w tym repozytorium. Zmiana modułu nie wymaga ręcznego kopiowania go do `CardputerZero/`. Samo `git pull` aktualizuje źródła, ale **nie zmienia aplikacji już zainstalowanej z `.deb`**. Po zmianie źródeł zbuduj nowy pakiet i zainstaluj go na urządzeniu.

## Moduły i wymagania

| Moduł | Wersja Cardputer Zero | Wymagania |
| --- | --- | --- |
| Recon | GUI skanu `iw`, wyniki strukturalne z istniejącego modułu; test sprzętowy wymagany | Wi-Fi w trybie managed, `iw` |
| Wardrive | GUI GPS + cykliczny skan + Wigle log; test sprzętowy wymagany | Wi-Fi, GPS z NMEA, `iw`, `stty` |
| ARP Scan | GUI bezpiecznego przeglądu połączonej sieci: ping + sąsiedzi ARP; test sprzętowy wymagany | Połączony IPv4, `ip`, `ping` |
| IP.CAM Finder | GUI kandydatów kamer z podłączonej sieci i istniejących heurystyk OUI; test sprzętowy wymagany | Połączony IPv4, `ip`, `ping` |
| Deauth | Ekran informacyjny, uruchamianie wyłączone | Adapter monitor, `iw`, `aireplay-ng`, opcjonalnie `mdk4`/`bully` |
| Portal | Ekran informacyjny, uruchamianie wyłączone | Adapter AP, `hostapd`, `dnsmasq`, `iptables` |
| Evil Twin | Ekran informacyjny, uruchamianie wyłączone | Dwa odpowiednie adaptery, `hostapd`, `dnsmasq` |
| Handshaker | Ekran informacyjny, uruchamianie wyłączone | Monitor, `aircrack-ng`, Scapy |
| WiFi Poet | Ekran informacyjny, uruchamianie wyłączone | Monitor, `mdk4` |
| Dragon Drain | Ekran informacyjny, uruchamianie wyłączone | Monitor, narzędzia budowania i źródła zewnętrzne |

Interfejs nie uruchamia operacji zakłócających sieć, podszywania się pod AP ani zbierania danych logowania. Pełne terminalowe kreatory ARP/IP.CAM potrafią łączyć się z wybraną siecią; GUI **nie wykonuje tej części**. Działa wyłącznie na już połączonym interfejsie i ogranicza przegląd do 128 adresów w podsieciach nie większych niż 4096 adresów. Recon korzysta z aktywnego skanu `iw`, więc nie jest snifferem pasywnym. Nie przełącza trybu karty. Brak uprawnień do skanowania jest wyświetlany jako błąd; GUI nie próbuje uruchomić się jako root.

## Menu i ekran startowy

Po uruchomieniu APPLaunch wyświetla `CardputerZero/swiss_intro.png` na ekranie 320 × 170. Po 2,5 sekundy u dołu pojawia się „PRESS ANY KEY”; dopiero następny klawisz otwiera menu. Ikona APPLaunch pochodzi z `CardputerZero/icon.png` i jest przygotowana jako `packaging/icon.png` (128 × 128).

Układ menu jest taki sam jak w terminalowym `swiss_knife.py`:

- **Recon** — bezpośrednio do informacji i konfiguracji Recon.
- **Attacks** — Deauth, Portal, Evil Twin, Handshaker, WiFi Poet, Dragon Drain, ARP scan, IP.CAM finder, Back.
- **Wardrive** — Start Wardrive, GPS setup, Back.
- **Exit** — powrót do APPLaunch.

Kolejność etykiet jest pobierana z menu terminalowego, a szczegóły modułów ze wspólnego silnika. Moduły bez ścieżki wykonania w GUI pokazują tylko informacje i diagnostykę zgodności.

## Sterowanie

| Klawisz | Działanie |
| --- | --- |
| `fn+F/X/Z/C` lub strzałki | Góra/dół/lewo/prawo |
| Enter | Wybór, uruchomienie po konfiguracji |
| Esc | Powrót; podczas operacji żądanie anulowania |
| `fn+K` (Home) | Menu główne; aktywna operacja jest anulowana |
| `fn+L/M` (PageUp/PageDown) | Szybsze przewijanie |
| Litery/cyfry/Backspace | Pole filtra SSID w konfiguracji |
| Przytrzymany Esc | Systemowy powrót do APPLaunch |

Kody kierunków, Home i PageUp/PageDown pochodzą z oficjalnego mapowania klawiatury. Aplikacja korzysta ze standardowych zdarzeń Linux evdev; ścieżkę urządzenia można podać przez `APPLAUNCH_KEYBOARD_DEVICE` lub `LV_LINUX_KEYBOARD_DEVICE`. Przy braku zmiennej wybierane jest wykryte urządzenie z Enter i Esc. Nie ma założenia, że adapter USB nazywa się `wlan1`.

## Budowanie pakietu

Na Linuxie z `python3`, `dpkg-deb` i `python3-pil`:

```bash
git clone https://github.com/CardputerZero/AppBuilder.git ../AppBuilder
APPBUILDER_DIR=../AppBuilder bash CardputerZero/scripts/build.sh
```

Wynik: `dist/swissknife-cardputer_0.1.2-m5stack1+git<N>.<SHA>_arm64.deb` (`N` to liczba commitów). Przy lokalnych zmianach bez commita do nazwy pliku dodawany jest znacznik `+dirty<CZAS>`. Aktualizacja zainstalowanego pakietu wymaga podniesienia `PKG_VERSION` w `packaging/meta.env`. Skrypt wywołuje **oficjalny** `AppBuilder/scripts/pack-deb.sh`. W repozytorium jest także [workflow GitHub Actions](../.github/workflows/cardputer-zero.yml), który pobiera aktualny AppBuilder, buduje pakiet i sprawdza, czy zawiera wspólny silnik oraz wpis APPLaunch. Oficjalny workflow „Build DEB Package” obecnie oczekuje projektu SCons, dlatego dla tego pakietu Pythona używany jest oficjalny pakowacz w naszym workflow.

`CardputerZero/app-builder.json` dostarcza pola do wykrycia projektu. Nie ma jeszcze sekcji `store`: publikacja w AppStore wymaga ustalenia licencji projektu, zrzutów 320 × 170 i przeprowadzenia testu na prawdziwym urządzeniu. Lokalny pakiet `.deb` i wpis APPLaunch nie wymagają publikacji w sklepie.

## Instalacja na Cardputer Zero

Skopiuj zbudowany `.deb`, a następnie na urządzeniu:

```bash
sudo apt install ./swissknife-cardputer_*.deb
```

Pakiet umieszcza program w `/usr/share/APPLaunch/apps/swissknife-cardputer/`, uruchamialny wrapper w `/usr/share/APPLaunch/bin/` i wpis `.desktop` w `/usr/share/APPLaunch/applications/`. APPLaunch powinien wykryć SwissKnife jako osobną aplikację. `postinst` dodaje użytkownika uruchamiającego `sudo` (lub `pi`, jeśli nie da się go ustalić) do istniejących grup `video`, `input`, `dialout` i `plugdev`. Jeśli APPLaunch działa na innym koncie, dodaj to konto do tych grup ręcznie. Zaloguj się ponownie lub uruchom urządzenie ponownie, aby członkostwo zadziałało. Pakiet nie zmienia profili sieciowych ani ustawień DHCP.

Wyniki są zapisywane pod `~/.local/state/swissknife/log/` użytkownika uruchamiającego APPLaunch. Po instalacji nowszego `.deb` pozostają w katalogu domowym.

## Tryb developerski

Na komputerze z Pythonem, Tkinter i Pillow:

```bash
python3 -m venv .venv
.venv/bin/pip install Pillow
.venv/bin/python -m CardputerZero.app.main --dev
```

Na Debianie/Ubuntu może być potrzebny pakiet `python3-tk`. Simulator pokazuje ekran w proporcjach 320 × 170, przykładowe `wlan0`/`wlan1`, GPS, statusy, wyniki, błędy i nawigację. Każdy ekran i wynik symulacji jest oznaczony `DEMO` lub `[SIMULATED]`. Uruchomienie `--dev` nie potwierdza działania na prawdziwym urządzeniu.

Testy bez sprzętu:

```bash
python3 -m unittest discover -s CardputerZero/tests -p 'test_*.py'
python3 -m unittest discover -s RPi_LCD_HAT -p 'test_*.py'
```

## Rozwiązywanie problemów i ograniczenia

- Czarny ekran: sprawdź `/dev/fb0`, format 320 × 170 × 16 bpp i uprawnienia grupy `video`.
- Brak reakcji klawiszy: sprawdź `/dev/input/`, grupę `input` i ścieżkę w `APPLAUNCH_KEYBOARD_DEVICE`.
- Brak GPS: sprawdź port `/dev/ttyUSB*`/`/dev/ttyACM*`, grupę `dialout` i rzeczywisty NMEA fix.
- Skan Wi-Fi odmawia dostępu: zwykły użytkownik może nie mieć uprawnień `nl80211`; aplikacja nie używa szerokiego `sudo` ani usługi root. W takim środowisku skan pozostaje niedostępny do czasu zaprojektowania wąsko uprawnionego pomocnika.
- Anulowanie przerywa bieżące wywołanie `iw`, odczyt NMEA i kolejne zadania skanowania LAN. Działające już procesy `ping` mają krótki limit czasu; działanie na Cardputer Zero wymaga testu urządzenia.
- Pojawienie się ikony w APPLaunch i wydajność framebuffer/klawiatury nie zostały jeszcze potwierdzone na urządzeniu.

SwissKnife jest przeznaczony do pracy w sieciach i na urządzeniach, do których masz uprawnienia.
