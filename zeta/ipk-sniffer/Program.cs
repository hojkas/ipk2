using System;
using System.Collections;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using CommandLine;
using PacketDotNet;
using SharpPcap;
using ProtocolType = PacketDotNet.ProtocolType;

// ReSharper disable CommentTypo

class Argument
{
  public int Port;
  public bool AllPorts;
  public int Num;
  public bool Tcp;
  public bool Udp;
  public string Inter;

  public Argument()
  {
    AllPorts = false;
    Tcp = true;
    Udp = true;
  }

  public class Options
  {
    [Option('t', "tcp", Required = false, HelpText = "Analyze TCP packets.")]
    public bool Tcp { get; set; }
    [Option('u', "udp", Required = false, HelpText = "Analyze UDP packets.")]
    public bool Udp { get; set; }
    [Option('i', Required = false, HelpText = "Interface to use for listening, leave empty for listing of all active.")]
    public string Interface { get; set; }
    [Option('p', Required = false, HelpText = "Port to use for listening, without this switch, program will listen to all.")]
    public int? Port { get; set; }
    [Option('n', Default = 1, Required = false, HelpText = "Number of packets to analyze, default value is 1.")]
    public int Num { get; set; }
  }

  /* Funkce zpracuje argumenty programu do proměnných třídy
  */
  public void parse_arguments(string[] args)
  {
    //Ověření zda argumenty obsahují --help nebo -h, pokud ano, výpiše se help message a program skončí
    foreach (string arg in args) {
      if (String.Compare(arg, "--help") == 0 || String.Compare(arg, "-h") == 0) {
        Console.WriteLine("Packet sniffer help\n-------------------\n" +
                          "Program starts listening and catches any packet that come across the selected device.\n" +
                          "If the received packet is from or to specified port in argument -p (if any)\n" +
                          "and if it is of the desired type (UDP/TCP given by corresponding switches),\n" +
                          "program extracts data from it and writes in on console screen (namely header with\n" +
                          "source and destination info, raw data in hexadecimal and their ascii representation).\n\n" +
                          "Possible arguments:\n" +
                          "-h / --help\n  Writes this message.\n" +
                          "-i name\n  Gives name of device to use for listening. If this switch is omitted, program will\n" +
                          "  list all active devices and end instead.\n" +
                          "-p number\n  Specifies port, only packets heading towards this port or originating from it\n" +
                          "  will be captured. If not used, program will capture packets relating to all ports.\n" +
                          "-n number\n  Number of packets to capture and write. If not specified, program will capture 1.\n" +
                          "-t / --tcp\n  Switch to capture TCP packets.\n" +
                          "-u / --udp\n  Switch to capture UDP packets.\n  If neither --tcp nor --udp is used, program " +
                          "captures both TCP and UDP packets.");
        Environment.Exit(0);
      }
    }
    // Parsování argumentů pomocí CommandLineParse
    Parser.Default.ParseArguments<Options>(args)
      .WithParsed<Options>(o =>
      {
        //Kontrola zda chyběl přepínač -i
        //V takovém případě načte aktivní zařízení, vypíše je a skončí program
        if(String.IsNullOrEmpty(o.Interface)) {
          //Načte zařízení do seznamu pro pozdější zpracování
          CaptureDeviceList dev_list = CaptureDeviceList.Instance;
          
          if (dev_list.Count < 1) {
            Console.WriteLine("No devices active on this machine.");
            Environment.Exit(0);
          }

          Console.WriteLine("Active devices:\n-----------");
          //Cyklus vypíše jména aktivních rozhraní
          foreach (ICaptureDevice dev in dev_list) {
            Console.WriteLine(dev.Name);
          }
          Environment.Exit(0);
        }

        // Kontrola validního čísla portu
        if (o.Port == null) {
          AllPorts = true;
        }
        else if (o.Port < 0 || o.Port > 65535) {
          Console.WriteLine("Invalid port number recieved (" + o.Port.ToString() + ").");
          Environment.Exit(1);
        }
        else Port = (int) o.Port;

        //Překopírování hodnot do members této třídy
        Num = o.Num;
        Inter = o.Interface;

        //Default hodnota tcp, udp je true, tímto se nastaví správně true/false
        //hodnoty (aby zadny prepinac/oba vyustily v obě hodnoty true)
        if(!o.Tcp && o.Udp) Tcp = false;
        if(!o.Udp && o.Tcp) Udp = false;
      });
  }
}


class PacketCapture
{
  private ICaptureDevice Device;

  /* Funkce najde v aktivnich rozhranich to s jmenem zadanym parametrem i a ulozi ho do promenne Device
   */
  public void find_device(string name)
  {
    CaptureDeviceList dev_list = CaptureDeviceList.Instance;
    bool found = false;
    
    //Cyklus projde available devices, a najde to se zadaným jménem a uloží
    if (dev_list.Count > 0) {
      foreach (ICaptureDevice dev in dev_list) {
        if (String.Equals(dev.Name, name)) {
          found = true;
          Device = dev;
        }
      }
    }

    //Pokud nebylo nalezeno v aktivnich rozhranich to se zadanym jmenem, vypise chybovou zpravu a ukonci program
    if (!found) {
      Console.WriteLine("No interface for listening with given name (" + name + ").");
      Environment.Exit(1);
    }
  }

  /*
   * Funkce s využitím knihovny SharpPCap zpracovává pakety.
   * Podle argumentů programu, které jí byly předány, apikuje filtr a ukončí se s návratovou funkcí false,
   * neodpovídal-li mu paket. Vytáhne si ze struktury IPPaket informace potřebné pro hlavičku, sestaví ji
   * a vypíše. Pro zpracování těla paketu volá funkci work_packet_body
   */
  private static bool work_packet(RawCapture raw, Argument arg)
  {
    //Extrahuje z rawCapture Packet (typ IPPacket, ze kterého lze lépe převzít informace)
    var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
    var ip = packet.Extract<IPPacket>();
    
    //Pokud je typ packetu TCP který podle parametrů nezachystáváme (nebo analogicky UDP který nezachystáváme)
    //nebo je-li jiného typu, funkce nic nevypíše a vrací false (tudíž counter se nezapočítá do celkového počtu)
    if (!arg.Tcp && ip.Protocol == ProtocolType.Tcp) return false;
    if (!arg.Udp && ip.Protocol == ProtocolType.Udp) return false;
    if (ip.Protocol != ProtocolType.Tcp && ip.Protocol != ProtocolType.Udp) return false;
    
    //Analyzuje o který packet jde a vytvoří verzi pro další zpracování
    bool isTcp = false; //false dále v programu == jde o udp
    TcpPacket PacTcp = null;
    UdpPacket PacUdp = null;
    bool PortChecksOut = true;
    
    if (ip.Protocol == ProtocolType.Tcp) {
      //TCP
      PacTcp = (TcpPacket) ip.PayloadPacket;
      isTcp = true;
    }
    else {
      //UDP
      PacUdp = (UdpPacket) ip.PayloadPacket;
    }

    //Vytvoří se string header a uloží se do něj v žádaném formátu čas přijetí paketu
    var date = raw.Timeval.Date;
    string header = date.Hour.ToString() + ":" + date.Minute.ToString() + ":" + date.Second.ToString() + "." +
                    date.Millisecond.ToString(); 
    
    //blok se pokusí přeložit ip adresu odesílatele, nenajde-li ji, uloží do stringu header pouze IP adresu
    try {
      IPHostEntry entry = Dns.GetHostEntry(ip.SourceAddress);
      header += " " + entry.HostName;
    }
    catch (SocketException) {
      header += " " + ip.SourceAddress.ToString();
    }
    
    int PortNum;
    //načte číslo portu z odpovídajícího paketu
    if (isTcp) PortNum = PacTcp.SourcePort;
    else PortNum =  PacUdp.SourcePort;

    //má-li se kontrolovat pouze jeden port, ověří zda je odesílatel ten port, pokud ne, uloží si informaci
    //že se zatím port nenašel, a přidá do hlavičky k vypsání číslo portu
    if(!arg.AllPorts)
      if (PortNum != arg.Port)
        PortChecksOut = false;
    header += " : " + PortNum.ToString();

    //blok se pokusi prelozit destination adress, pokud nenajde, ulozi do hlavicky k vypsani IP adresu místo toho
    try {
      IPHostEntry entry = Dns.GetHostEntry(ip.DestinationAddress);
      header += " > " + entry.HostName;
    }
    catch (SocketException) {
      header += " > " + ip.DestinationAddress.ToString();
    }
    
    if (isTcp) PortNum = PacTcp.DestinationPort;
    else PortNum = PacUdp.DestinationPort;
    //Pokud první port byl vyhodnocen jako neodpovídající (aka hledalo se číslo portu, ne všechny, a nebyl to on),
    //a zárveň ani zde číslo neodpovídá hledanému, funkce vrací false a vše do tohoto momentu zpracovávané se zahazuje
    if (!PortChecksOut && PortNum != arg.Port) return false; 
    header += " : " + PortNum.ToString() + "\n";

    //Vypíše zpracovanou hlavičku, v tento moment už je jisté že zpracováváme paket který prošel filtry
    Console.WriteLine(header);
    
    parse_packet_body(raw);
    return true;
  }

  private static void parse_packet_body(RawCapture raw)
  {
    int counter = 0;
    int worked = 0;
    string line = "";
    string end = " ";
    //Cyklus prochází byte po bytu data rawCapture, vypisuje je a formátuje
    foreach (byte b in raw.Data) {
      //Začátek řádku
      if (counter == 0) {
        line = "0x" + worked.ToString("x4") + ":  ";
        end = " ";
      }
      line += b.ToString("x2") + " ";
      if (Char.IsControl(Convert.ToChar(b)) || Convert.ToInt32(b) > 127) end += ".";
      else end += Convert.ToChar(b);
      //V prostřed vypisování, po 8. bytu udělá o mezeru navíc kvůli formátu
      if (counter == 7) {
        line += " ";
        end += " ";
      }
      counter++;
      //Je-li načteno již 16 bytů, ukončí výpis řádku a přejde na další
      if (counter == 16) {
        Console.WriteLine(line + end);
        counter = 0;
      }
      worked++;
    }
  }
  
  public void catch_packets(Argument arg)
  {
    //Otevře Device pro naslouchání s nastaveným timeoutem
    int timeout = 2000;
    int counter = 0;
    Device.Open(DeviceMode.Promiscuous, timeout);
    RawCapture packet;

    // Cyklus načítá pakety
    while ((packet = Device.GetNextPacket()) != null) {
      //Volá funkci na zpracování paketu a pokud vrátí true (např. pokud jde o TCP protokol když
      //je zvolena funkce na naslouchání tcp, zvýší counter
      if (work_packet(packet, arg)) {
        counter++;
        if(counter != arg.Num) Console.WriteLine("");
      }
      if (counter == arg.Num) break;
    }

    Device.Close();
  }
}


class Program
{ 
  /* Main
   * Volá zpracování argumentů a poté funkci na chytání paketů
   */
  static void Main(string[] args)
  {
    Argument arg = new Argument();
    PacketCapture pc = new PacketCapture();
    arg.parse_arguments(args);
    //arg.parse_debug();
    pc.find_device(arg.Inter);
    pc.catch_packets(arg);
  }
}
