# ipk-sniffer

Letní 2019/2020

Body: 7/20

Implementace 2. projektu (verze ZETA) do předmětu IPK.

### O programu

Program slouží na zachytávání paketů a vypisování informací o nich. Dělá tak s využitím knihovny *SharpPCap*. Otevře rozhraní podle parametru a otevře ho pro naslouchání, poté na něm zachytává pakety a posílá je ke zpracování. Extrahují se informace do hlavičky jako čísla portů, čas a ip adresy, které se pokusí přeložit na doménová jména. Poté se obsah paketu ve formátu bytů zpracuje do žádaného formátu a vypíše.

Výstup na konzoli obsahuje pro každý paket hlavičku následovanou výpisem celýho paketu v hexadecimálním zápisu a ASCII reprezentaci. (Formátem i rozsahem výpis paketu odpovídá zobrazení paketu ve Wiresharku.)

Zvolila jsem variantu otevření zařízení pro naslouchání s timeoutem, program se ukončí pokud 10s nepřišel paket nebo pokud dosáhl svého cíle a zpracoval určený počet paketů.

### Spouštění

*Důležité*: Pro správný průběh musí být program spuštěn jako super user (např. `sudo ./ipk-sniffer -i any`). Bez těchto oprávnění nemusí být možné otevřít rozhraní pro naslouchání.

Pro překlad aplikace pomocí přiloženého Makefile:

`make` (popř. `make build`)

Vzniklý soubor *ipk-sniffer* lze spustit jednoduchým příkazem pro otestování funkcionality:

`make run` (pouze spustí program a na rozhraní any zachytí jeden paket, odpovídá příkazu `./ipk-sniffer -i any`)

Pro vyčištění všech vytvořených souborů:

`make clean`

Pro důkladnější testování je vhodné spouštět program přímo z příkazové řádky s vhodnou kombinací následujících parametrů (v libovolném pořadí):

* `-i name` Program bude naslouchat na rozhraní s daným jménem, existuje-li takové. Pokud je tento parametr vynechán, výpíše se seznam aktivních rozhraní.
* `-p port` Určí číslo portu, na němž bude program naslouchat. Bude pracovat pouze s těmi pakety, které buď vychází z portu daného čísla nebo z něj odchází. Je-li parametr vynechán, zpracovává pakety bez ohledu na port.
* `-n num` Určí počet paketů, které se mají zachytit a vypsat. Není-li specifikováno, program zpracuje jeden.
* `-t, --tcp` Povolí zachytávání TCP paketů. (Není-li použit žádný parametr specifikující tcp/udp filtr, program zachytává oboje implicitně)
* `-u, --udp` Povolí zachytávání UDP paketů.

Např. pro výpis 5 TCP paketů na rozhraní *any* mířících na port 55 či odcházejících z něj:

`./ipk-sniffer -i any -p 55 -t -n 5`

### Poznámka k výstupu:

Vypsaná data nejsou oddělena prádzným řádkem na dvě části, jak tomu je v zadání. V zadání není uvedeno, z jakého důvodu tam oddělení existuje. Inspirovala jsem se tedy výpisem velmi podobného druhu ve Wiresharku, a vypsala data paketu celá a bez rozdělení jako v tomto nástroji.

### Odevzdané soubory

* Makefile
* ipk-sniffer.cs
* ipk-sniffer.csproj
* README
* manual.pdf
