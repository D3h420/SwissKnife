# SwissKnife dla Cardputer Zero

**LAB5 / D3h420** · aplikacja 320 × 170 dla Raspberry Pi OS i APPLaunch.

## Stan implementacji

To niezależny interfejs do istniejącego SwissKnife. Kod modułów pozostaje w `../modules/`, a wspólne API, katalog funkcji, wykrywanie sprzętu i ścieżki danych w `../core/`. Aplikacja nie zawiera kopii modułów. GUI uruchamia się jako zwykły użytkownik; istniejące skrypty wymagające roota są wywoływane przez kontrolowany proces. Terminalowy `swiss_knife.py` pozostaje drugim wejściem do tego samego silnika.

Kod działa w trybie symulacji na komputerze. Poprzedni pakiet 0.2.0 zainstalowano na fizycznym Cardputer Zero z Debianem 13; potwierdzono dostęp do ekranu 320 × 170, klawiatury oraz uruchomienie i anulowanie terminalowego Recon z jego oryginalnym menu. Wcześniejszy skan Recon na `wlan0` także został sprawdzony. Pakiet 0.2.1 z nowym wyglądem zbudowano lokalnie, ale nie udało się go jeszcze zainstalować, ponieważ `c0.local` przestał odpowiadać. Pozostałe moduły, adaptery i pełna obsługa GUI wymagają testów sprzętowych.

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
                ├── core/ + modules/ + html/
CardputerZero/ ─┘
```

`core/engine.py` udostępnia listę modułów, status zależności i sprzętu oraz operacje z wynikami, błędami i anulowaniem. Dla wszystkich pozycji menu uruchamia **ten sam plik modułu**, którego używa terminal. Warstwa wejścia przechwytuje terminalowe pytania `input`, `getpass` i `stdin.readline`, aby odpowiedzi dało się wpisać fizyczną klawiaturą. Skrypt działa w osobnym procesie, a GUI odczytuje zdarzenia bez blokowania ekranu. `core/hardware.py` wykrywa interfejsy, USB, GPS, trasę domyślną, narzędzia i uprawnienia.

Uprawnienia root otrzymuje tylko proces uruchamiający wybrany moduł. Pomocnik w pakiecie przyjmuje wyłącznie nazwy z `core/features.py` i mapuje je na pliki wspólnego silnika. GUI nie otrzymuje ogólnego `sudo` ani możliwości podania dowolnej komendy. Anulowanie wysyła przerwanie procesowi modułu, aby istniejąca obsługa `KeyboardInterrupt` mogła posprzątać interfejsy i procesy potomne; zachowanie tego mechanizmu wymaga testu na urządzeniu.

Zależności kodu są pobierane **podczas każdego budowania pakietu** z aktualnych katalogów `core/`, `modules/`, `html/` i `swiss_knife.py` w tym repozytorium. Zmiana modułu nie wymaga ręcznego kopiowania go do `CardputerZero/`. Samo `git pull` aktualizuje źródła, ale **nie zmienia aplikacji już zainstalowanej z `.deb`**. Po zmianie źródeł zbuduj nowy pakiet i zainstaluj go na urządzeniu.

## Moduły i wymagania

| Moduł | Ścieżka uruchamiania | Główne wymagania |
| --- | --- | --- |
| Recon | `modules/recon.py` | Wi-Fi, `iw`; funkcje monitor wymagają zgodnego adaptera |
| Start Wardrive / GPS setup | `modules/wardrive.py` | Wi-Fi, odbiornik GPS i poprawny strumień NMEA |
| ARP scan | `modules/arp_scanner.py` | Połączenie IPv4, narzędzia sieciowe |
| IP.CAM finder | `modules/ipcam_finder.py` | Połączenie IPv4, narzędzia sieciowe |
| Deauth | `modules/deauth.py` | Zgodny adapter monitor, Aircrack-ng; opcjonalnie `mdk4`/`bully` |
| Portal | `modules/portal.py` | Adapter AP, `hostapd`, `dnsmasq`, `iptables` |
| Evil Twin | `modules/twins.py` | Odpowiednie adaptery AP i monitor, `hostapd`, `dnsmasq` |
| Handshaker | `modules/handshaker.py` | Adapter monitor, Aircrack-ng, Scapy |
| WiFi Poet | `modules/wifi_poet.py` | Adapter monitor, `mdk4` i biblioteki Python |
| Dragon Drain | `modules/dragon_drain.py` | Specjalistyczne narzędzia i źródła zewnętrzne |

Opis modułu ma jeden przycisk Start; Enter uruchamia funkcję bez dodatkowego ekranu potwierdzenia. Pozycje uruchamiają wspólne moduły Python. Numerowane wybory są pokazywane jako karty, pola tekstowe obsługuje klawiatura. Recon przesyła wyniki skanu i sniffera jako rekordy sieci. Wardrive pokazuje bieżące sieci i licznik zapisów, ARP scan urządzenia, a IP.CAM finder kandydatów kamer. GUI pokazuje te dane w kartach z osobnym widokiem szczegółów. Pozostałe moduły korzystają z graficznego wyboru numerowanych opcji, lecz ich wyniki nadal wymagają osobnych widoków danych; nie są jeszcze pełną nakładką graficzną. Funkcje zależne od trybu monitorowania, AP, GPS lub zewnętrznych źródeł nadal wymagają zgodnego sprzętu i testów. Root nie zastąpi brakującego narzędzia ani możliwości adaptera. Część modułów może zmienić tryb interfejsu lub profil sieci i przerwać połączenie używane do SSH; przed uruchomieniem wybierz kartę przeznaczoną do danej operacji.

## Menu i ekran startowy

Po uruchomieniu APPLaunch wyświetla `CardputerZero/swiss_intro.png` na ekranie 320 × 170. Po 2,5 sekundy u dołu pojawia się „PRESS ANY KEY”; dopiero następny klawisz otwiera menu. Ikona APPLaunch pochodzi z `CardputerZero/icon.png` i jest przygotowana jako `packaging/icon.png` (128 × 128).

Układ menu jest taki sam jak w terminalowym `swiss_knife.py`:

- **Recon** — otwiera widok modułu i jego uruchomienie.
- **Attacks** — Deauth, Portal, Evil Twin, Handshaker, WiFi Poet, Dragon Drain, ARP scan, IP.CAM finder, Back.
- **Wardrive** — Start Wardrive, GPS setup, Back.
- **Exit** — powrót do APPLaunch.

Kolejność etykiet jest pobierana z menu terminalowego, a szczegóły modułów ze wspólnego silnika. Po uruchomieniu modułu aplikacja pokazuje jego bieżące wyjście i pytania. Wybory wewnątrz modułu są tymi samymi wyborami co w terminalu.

## Sterowanie

| Klawisz | Działanie |
| --- | --- |
| `fn+F/X/Z/C` lub strzałki | Góra/dół/lewo/prawo |
| Enter | Wybór lub wysłanie wpisanej odpowiedzi do modułu |
| Esc | Powrót; podczas operacji żądanie przerwania modułu |
| `fn+K` (Home) | Menu główne; aktywny moduł jest przerywany |
| `fn+L/M` (PageUp/PageDown) | Szybsze przewijanie |
| Litery/cyfry/Backspace | Edycja odpowiedzi na pytanie modułu; hasła są ukryte |
| Przytrzymany Esc | Systemowy powrót do APPLaunch |

Kody kierunków, Home i PageUp/PageDown pochodzą z oficjalnego mapowania klawiatury. Aplikacja korzysta ze standardowych zdarzeń Linux evdev; ścieżkę urządzenia można podać przez `APPLAUNCH_KEYBOARD_DEVICE` lub `LV_LINUX_KEYBOARD_DEVICE`. Przy braku zmiennej wybierane jest wykryte urządzenie z Enter i Esc. Nie ma założenia, że adapter USB nazywa się `wlan1`.

## Budowanie pakietu

Na Linuxie z `python3`, `dpkg-deb` i `python3-pil`:

```bash
git clone https://github.com/CardputerZero/AppBuilder.git ../AppBuilder
APPBUILDER_DIR=../AppBuilder bash CardputerZero/scripts/build.sh
```

Wynik: `dist/swissknife-cardputer_0.2.3-m5stack1+git<N>.<SHA>_arm64.deb` (`N` to liczba commitów). Przy lokalnych zmianach bez commita do nazwy pliku dodawany jest znacznik `+dirty<CZAS>`. Aktualizacja zainstalowanego pakietu wymaga podniesienia `PKG_VERSION` w `packaging/meta.env`. Skrypt wywołuje **oficjalny** `AppBuilder/scripts/pack-deb.sh`. W repozytorium jest także [workflow GitHub Actions](../.github/workflows/cardputer-zero.yml), który pobiera aktualny AppBuilder, buduje pakiet i sprawdza, czy zawiera wspólny silnik oraz wpis APPLaunch. Oficjalny workflow „Build DEB Package” obecnie oczekuje projektu SCons, dlatego dla tego pakietu Pythona używany jest oficjalny pakowacz w naszym workflow.

`CardputerZero/app-builder.json` dostarcza pola do wykrycia projektu. Nie ma jeszcze sekcji `store`: publikacja w AppStore wymaga ustalenia licencji projektu, zrzutów 320 × 170 i przeprowadzenia testu na prawdziwym urządzeniu. Lokalny pakiet `.deb` i wpis APPLaunch nie wymagają publikacji w sklepie.

## Instalacja na Cardputer Zero

Na komputerze, na którym zbudowano pakiet, uruchom:

```bash
bash CardputerZero/scripts/deploy.sh dist/swissknife-cardputer_0.2.3-*_arm64.deb one@c0.local
```

Skrypt przygotowuje pliki pakietu z właścicielem `root`, kopiuje `.deb` do `/tmp` na Cardputerze, instaluje go przez `apt --no-install-recommends` i usuwa przesłany plik także wtedy, gdy instalacja się nie powiedzie. Aktualizacja pakietu przez `apt` zastępuje poprzednią wersję; dane użytkownika w katalogu domowym pozostają na miejscu.

Pakiet umieszcza program w `/usr/share/APPLaunch/apps/swissknife-cardputer/`, uruchamialny wrapper w `/usr/share/APPLaunch/bin/` i wpis `.desktop` w `/usr/share/APPLaunch/applications/`. APPLaunch powinien wykryć SwissKnife jako osobną aplikację. `apt` instaluje zależności zadeklarowane w pakiecie, między innymi Aircrack-ng, Scapy, `hostapd`, `dnsmasq-base`, `mdk4`, `bully`, narzędzia ARP i sieciowe. Dragon Drain może dodatkowo instalować/budować własne narzędzia przy pierwszym uruchomieniu; wymaga to osobnego testu na Debianie 13. Pakiet nie uruchamia automatycznie usług AP/DHCP.

`postinst` dodaje użytkownika uruchamiającego `sudo` (lub konto o UID 1000) do istniejących grup `video`, `input`, `dialout` i `plugdev`. Jeśli APPLaunch działa na innym koncie, dodaj to konto do tych grup ręcznie. Zaloguj się ponownie lub uruchom urządzenie ponownie, aby członkostwo zadziałało. Reguła `sudoers` zezwala temu użytkownikowi uruchamiać tylko pomocnik skanowania Wi-Fi i `/usr/libexec/swissknife-cardputer/run-module` z nazwą modułu z katalogu funkcji. Pomocnik modułów sprawdza pliki pakietu i używa ustalonego interpretera Pythona. Reguła jest usuwana przy odinstalowaniu. Instalacja pakietu nie zmienia profili sieciowych ani ustawień DHCP; wybrany moduł może to robić podczas pracy, tak samo jak wersja terminalowa.

Logi interfejsu są zapisywane pod `~/.local/state/swissknife/log/` użytkownika uruchamiającego APPLaunch. Pliki tworzone przez moduły działające jako root znajdują się pod `/var/lib/swissknife/`. Dane te nie są częścią pakietu i pozostają po jego aktualizacji.

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
```

## Rozwiązywanie problemów i ograniczenia

- Czarny ekran: sprawdź `/dev/fb0`, format 320 × 170 × 16 bpp i uprawnienia grupy `video`.
- Brak reakcji klawiszy: sprawdź `/dev/input/`, grupę `input` i ścieżkę w `APPLAUNCH_KEYBOARD_DEVICE`.
- Brak GPS: sprawdź port `/dev/ttyUSB*`/`/dev/ttyACM*`, grupę `dialout` i rzeczywisty NMEA fix.
- Skan Wi-Fi odmawia dostępu: sprawdź, czy instalacja pakietu utworzyła `/etc/sudoers.d/swissknife-cardputer`, czy użytkownik uruchamiający APPLaunch jest w tej regule oraz czy `iw dev <interfejs> info` rozpoznaje adapter. Pomocnik nie zmienia trybu karty ani profili sieciowych.
- Anulowanie przerywa bieżące wywołanie `iw`, odczyt NMEA i kolejne zadania skanowania LAN. Działające już procesy `ping` mają krótki limit czasu; działanie na Cardputer Zero wymaga testu urządzenia.
- Pojawienie się ikony w APPLaunch i wydajność framebuffer/klawiatury nie zostały jeszcze potwierdzone na urządzeniu.

SwissKnife jest przeznaczony do pracy w sieciach i na urządzeniach, do których masz uprawnienia.
