using System;
using PacketDotNet;
using CommandLine;

class Argument
{
  public string rozhrani;
  public int port;
  public bool tcp;
  public bool ucp;
  public int num;

  public Argument()
  {
    rozhrani = null;
    tcp = false;
    ucp = false;
    num = 1;
  }

  public class Options
  {
    [Option('t', "tcp", Required = false, HelpText = "Analyze TCP packets.")]
    public bool Tcp { get; set; }
    [Option('u', "udp", Required = false, HelpText = "Analyze UDP packets.")]
    public bool Udp { get; set; }
  }

  public void parse_arguments(string[] args)
  {
    string shortopts = "tui:p:n:";
    Parser.Default.ParseArguments<Options>(args)
      .WithParsed<Options>(o =>
      {
        if(o.Tcp) {
          Console.WriteLine("TCP on");
        }

        if(o.Udp) {
          Console.WriteLine("UDP on");
        }

      });
  }
}

class Program
{
  static void Main(string[] args)
  {
    Argument arg = new Argument();
    arg.parse_arguments(args);
  }
}
