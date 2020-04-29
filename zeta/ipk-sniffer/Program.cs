using System;
using PacketDotNet;
using CommandLine;

class Argument
{
  public int port;
  public bool all_ports;
  public int num;
  public bool tcp;
  public bool udp;
  public string inter;

  public Argument()
  {
    all_ports = false;
    tcp = true;
    udp = true;
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
        if(String.IsNullOrEmpty(o.Interface)) {
          //TODO handle missing interface (print stuff)
          Environment.Exit(0);
        }

        // Kontrola validního čísla portu
        if(o.Port < 0) {
          Console.WriteLine("Invalid port number recieved (" + o.Port.ToString() + ").");
          Environment.Exit(1);
        }
        if(o.Port == 0) all_ports = true;

        //Překopírování hodnot do members této třídy
        port = o.Port;
        num = o.Num;
        inter = o.Interface;

        //Default hodnota tcp, udp je true, tímto se nastaví správně true/false
        //hodnoty (aby zadny prepinac/oba vyustily v obě hodnoty true)
        if(!o.Tcp && o.Udp) tcp = false;
        if(!o.Udp && o.Tcp) udp = false;
      });

  }

  public void parse_debug()
  {
    Console.WriteLine("Interface: " + inter);
    Console.WriteLine("How many packet: " + num.ToString());
    if(all_ports) Console.WriteLine("All ports");
    else Console.WriteLine("Port: " + port.ToString());
    if(tcp && udp) Console.WriteLine("TCP & UDP");
    else
      if(tcp) Console.WriteLine("TCP only");
      else if(udp) Console.WriteLine("UDP only");
      else Console.WriteLine("Shouldn't happen, no tcp/udp");
  }
}

class Program
{
  static void Main(string[] args)
  {
    Argument arg = new Argument();
    arg.parse_arguments(args);
    arg.parse_debug();
  }
}
