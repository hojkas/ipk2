using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using CommandLine;
using SharpPcap;
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
    public int Port { get; set; }
    [Option('n', Default = 1, Required = false, HelpText = "Number of packets to analyze, default value is 1.")]
    public int Num { get; set; }
  }

  /* Funkce zpracuje argumenty programu do proměnných třídy
  */
  public void parse_arguments(string[] args)
  {
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
        if(o.Port < 0) {
          Console.WriteLine("Invalid port number recieved (" + o.Port.ToString() + ").");
          Environment.Exit(1);
        }
        if(o.Port == 0) AllPorts = true;

        //Překopírování hodnot do members této třídy
        Port = o.Port;
        Num = o.Num;
        Inter = o.Interface;

        //Default hodnota tcp, udp je true, tímto se nastaví správně true/false
        //hodnoty (aby zadny prepinac/oba vyustily v obě hodnoty true)
        if(!o.Tcp && o.Udp) Tcp = false;
        if(!o.Udp && o.Tcp) Udp = false;
      });
  }

  public void parse_debug()
  {
    Console.WriteLine("Interface: " + Inter);
    Console.WriteLine("How many packet: " + Num.ToString());
    if(AllPorts) Console.WriteLine("All ports");
    else Console.WriteLine("Port: " + Port.ToString());
    if(Tcp && Udp) Console.WriteLine("TCP & UDP");
    else
      if(Tcp) Console.WriteLine("TCP only");
      else if(Udp) Console.WriteLine("UDP only");
      else Console.WriteLine("Shouldn't happen, no tcp/udp");
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

  private static void work_packet(RawCapture p)
  {
    Console.WriteLine(p.ToString());
    //ParsePacket
    //Exract
  }
  
  public void catch_packets(Argument arg)
  {
    //Otevře Device pro naslouchání s nastaveným timeoutem
    int timeout = 2000;
    int counter = 0;
    Device.Open(DeviceMode.Promiscuous, timeout);
    RawCapture packet = null;

    //TODO delete
    Console.WriteLine("[DEBUG] Listening started\n-----");
    
    // Cyklus načítá pakety
    while ((packet = Device.GetNextPacket()) != null) {
      work_packet(packet);
      counter++;
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
