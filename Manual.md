---
title: Manual
subtitle: IPK Sniffer
author: Iveta Strnadová
login: xstrna14
---

<div style="text-align:center; margin-top:38.2%">
    <hspace></hspace>
    <h1>
        Manual
    </h1>
    <h3>
        IPK-sniffer
    </h3>
    <p style="margin-top:10%"></p>
    <h5>
        Počítačové komunikace a sítě<br>
    </h5>
    <p style="margin-top:10%"></p>
    <h3>
        Dokumentace k 2. projektu
    </h3>
    <p style="margin-top:10%"></p>
    Iveta Strnadová<br>
    xstrna14
</div>
<p style="text-align:center; margin-top:60%">3. května 2020</p>




<div style="page-break-after: always; break-after: page;"></div>

[toc]

<div style="page-break-after: always; break-after: page;"></div>

# 1. Úvod

## Zadání

Navrhněte a implementujte síťový analyzátor v C/C++/C#, který bude schopný na určitém síťovém rozhraním zachytávat a filtrovat pakety.

## Návrh aplikace

### Jazyk a knihovny

Pro implementaci jsem zvolila jazyk C#. Na práci s pakety jsou použity prostředky knihovny *SharpPCap* a *PacketDotNet*. Zpracování argumentů z příkazové řádky probíhá pomocí knihovny *CommandLineParser*.

### Struktura programu

Program byl rozdělen do funkcí různých tříd podle cíle a prostředků potřebných pro jejich vykonání. Základem návrhu se staly dvě třídy, *Argument* a *CapturePacket*. Mimo ně by existovala ještě třída *Program* s funkcí *main*, jejímž účelem by bylo pouze vytvořit důležité objekty a zavolat jejich funkce pro naslouchání paketů.

Třída *Argument*  byla navrhnuta pro zpracování argumentů programu a uchování důležitých hodnot pro další části. Uvnitř by zapouzdřovala použití knihovny *CommandLineParser* a přidávala vlastní kontroly parametrů a jejich vyhodnocování pro snazší použití později.

Třída *CapturePacket* byla modelována jako jádro programu. Pomocí knihovny *SharpPCap* by se starala o otevření zařízení pro naslouchání i samotné filtrování a zpracování paketů. K filtrování by používala prostředky instance třídy *Argument*.

# 2. Implementace

# 3. Testování





