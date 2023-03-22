#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/gnuplot.h"
#include <string>
#include <fstream>
#include <bits/stdc++.h>

using namespace ns3;

typedef uint32_t uint;

uint packetSize = 1500;

NS_LOG_COMPONENT_DEFINE("Assignment4");

// Customised application
class MyApp : public Application 
{
public:

  MyApp();
  virtual ~MyApp();

  void Setup(Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);
  void setRate(DataRate newRate);

private:
  virtual void StartApplication(void);
  virtual void StopApplication(void);

  void ScheduleTx(void);
  void SendPacket(void);
	
  Ptr<Socket>     m_socket;
  Address         m_peer;
  uint32_t        m_packetSize;
  uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_sendEvent;
  bool            m_running;
  uint32_t        m_packetsSent;
};

MyApp::MyApp()
  : m_socket(0), 
    m_peer(), 
    m_packetSize(0), 
    m_nPackets(0), 
    m_dataRate(0), 
    m_sendEvent(), 
    m_running(false), 
    m_packetsSent(0)
{
}

MyApp::~MyApp()
{
  m_socket = 0;
}

void
MyApp::Setup(Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
{
  m_socket = socket;
  m_peer = address;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
}

void
MyApp::StartApplication(void)
{
  m_running = true;
  m_packetsSent = 0;
  m_socket->Bind();
  m_socket->Connect(m_peer);
  SendPacket();
}

void 
MyApp::StopApplication(void)
{
  m_running = false;

  if(m_sendEvent.IsRunning())
    {
      Simulator::Cancel(m_sendEvent);
    }

  if(m_socket)
    {
      m_socket->Close();
    }
}

void 
MyApp::SendPacket(void)
{
  Ptr<Packet> packet = Create<Packet>(m_packetSize);
  m_socket->Send(packet);

  if(++m_packetsSent < m_nPackets)
    {
      ScheduleTx();
    }
}

void 
MyApp::ScheduleTx(void)
{
  if(m_running)
    {
      Time tNext(Seconds(m_packetSize * 8 / static_cast<double>(m_dataRate.GetBitRate())));
      m_sendEvent = Simulator::Schedule(tNext, &MyApp::SendPacket, this);
    }
}

void 
MyApp::setRate(DataRate newRate)
{
	m_dataRate = newRate;
	return;
}

// Global Variables and function prototypes

// store source and destination of TCP and UDP connections
std::map<std::pair<Ipv4Address, Ipv4Address>, uint16_t> tcpSet, udpSet;
 
Gnuplot2dDataset dataiTCPvR[4], dataiUDPvR[2];
Gnuplot2dDataset datatcpTPvR, dataudpTPvR;

uint16_t n_tcp = 0; // Used for indexing tcp connections

void setTCPconnection(NodeContainer &H, Ipv4InterfaceContainer &iface, Ipv4InterfaceContainer &iface1, int source, int sink, int bufferSize, int port);

uint16_t n_udp = 0; // Used for indexing udp connections

Ptr<MyApp> setUDPconnection(NodeContainer &H, Ipv4InterfaceContainer &iface, Ipv4InterfaceContainer &iface1, int source, int sink, int bufferSize, int port);

uint curRate = 20;

void IncRate(Ptr<MyApp> app, DataRate newRate, FlowMonitorHelper *flowMonitorHelp, Ptr<FlowMonitor> flowMonitor);

void makeDataSet(Gnuplot2dDataset &dataset, std::string name);

void getPlot(std::string fname, std::string title, std::string legendx, std::string legendy, std::string extra, Gnuplot2dDataset &dataset);



int main(int argc, char *argv[])
{
	// Set smallest measurable time interval to 1 ns.
	Time::SetResolution(Time::NS);
	
	// Setting defualt configuration to TCP New Reno
	Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(TcpNewReno::GetTypeId()));
	
	// Initialize datasets
	Gnuplot2dDataset DataTPvBS;
	makeDataSet(DataTPvBS, "Total Throughput vs BufferSize");
	Gnuplot2dDataset DatatcpTPvBS;
	makeDataSet(DatatcpTPvBS, "TCP Throughput vs BufferSize");
	Gnuplot2dDataset DataudpTPvBS;
	makeDataSet(DataudpTPvBS, "UDP Throughput vs BufferSize");
	Gnuplot2dDataset DataFairvBS;
	makeDataSet(DataFairvBS, "Fairness vs BufferSize");
	
	makeDataSet(datatcpTPvR, "TCP throughput vs UDP Rate");
	makeDataSet(dataudpTPvR, "UDP throughput vs UDP Rate");
	
	for(int i=0;i<4;i++)
	{
		std::string label = "TCP ";
		label = label + std::to_string(i);
		label = label +  " vs UDP Rate";
		makeDataSet(dataiTCPvR[i], label); 
	}
	for(int i=0;i<2;i++)
	{
		std::string label = "UDP ";
		label = label + std::to_string(i);
		label = label +  " vs UDP Rate";
		makeDataSet(dataiUDPvR[i], label); 
	}
	int flag = 1;
	
	// Varying buffer size
	for(uint bufferSize = 10*packetSize; bufferSize <= 800*packetSize; )
	{
		NodeContainer H, R;
		
		// Host nodes
		H.Create(6);
		
		// Router Nodes
		R.Create(2);
		
		// Create Links 
		NodeContainer n_H1R1 = NodeContainer(H.Get(0), R.Get(0));
		NodeContainer n_H2R1 = NodeContainer(H.Get(1), R.Get(0));
		NodeContainer n_H3R1 = NodeContainer(H.Get(2), R.Get(0));
		NodeContainer n_H4R2 = NodeContainer(H.Get(3), R.Get(1));
		NodeContainer n_H5R2 = NodeContainer(H.Get(4), R.Get(1));
		NodeContainer n_H6R2 = NodeContainer(H.Get(5), R.Get(1));
		NodeContainer n_R1R2 = NodeContainer(H.Get(0), R.Get(1));

		// Install protocols
		InternetStackHelper ISH;
		ISH.Install(H);
		ISH.Install(R);
		
		PointToPointHelper p2p;
		
		p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
		p2p.SetChannelAttribute("Delay", StringValue("10ms"));
		
		NetDeviceContainer nd_H1R1 = p2p.Install(n_H1R1);
		NetDeviceContainer nd_H2R1 = p2p.Install(n_H2R1);
		NetDeviceContainer nd_H3R1 = p2p.Install(n_H3R1);
		NetDeviceContainer nd_H4R2 = p2p.Install(n_H4R2);
		NetDeviceContainer nd_H5R2 = p2p.Install(n_H5R2);
		NetDeviceContainer nd_H6R2 = p2p.Install(n_H6R2);
		
		p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
		p2p.SetChannelAttribute("Delay", StringValue("100ms"));
		p2p.SetQueue("ns3::DropTailQueue", "MaxSize", QueueSizeValue(QueueSize("85p")));
		
		NetDeviceContainer nd_R1R2 = p2p.Install(n_R1R2);
		
		// Setup IP addresses
		Ipv4AddressHelper ipv4;
		
		ipv4.SetBase("10.1.1.0", "255.255.255.0");
		Ipv4InterfaceContainer i_H1R1 = ipv4.Assign(nd_H1R1);
		
		ipv4.SetBase("10.1.2.0", "255.255.255.0");
		Ipv4InterfaceContainer i_H2R1 = ipv4.Assign(nd_H2R1);
		
		ipv4.SetBase("10.1.3.0", "255.255.255.0");
		Ipv4InterfaceContainer i_H3R1 = ipv4.Assign(nd_H3R1);
		
		ipv4.SetBase("10.1.4.0", "255.255.255.0");
		Ipv4InterfaceContainer i_H4R2 = ipv4.Assign(nd_H4R2);
		
		ipv4.SetBase("10.1.5.0", "255.255.255.0");
		Ipv4InterfaceContainer i_H5R2 = ipv4.Assign(nd_H5R2);
		
		ipv4.SetBase("10.1.6.0", "255.255.255.0");
		Ipv4InterfaceContainer i_H6R2 = ipv4.Assign(nd_H6R2);
		
		ipv4.SetBase("10.1.7.0", "255.255.255.0");
		Ipv4InterfaceContainer i_R1R2 = ipv4.Assign(nd_R1R2);
		
		Ipv4GlobalRoutingHelper::PopulateRoutingTables();
		
		// TCP connections
		
		// h2 ---> h1
		setTCPconnection(H, i_H1R1, i_H2R1, 1, 0, bufferSize, 7001);
		
		// h3 ---> h6
		setTCPconnection(H, i_H6R2, i_H3R1, 2, 5, bufferSize, 7002);
		
		// h4 ---> h6
		setTCPconnection(H, i_H6R2, i_H4R2, 3, 5, bufferSize, 7003);
		
		// h5 ---> h2
		setTCPconnection(H, i_H2R1, i_H5R2, 4, 1, bufferSize, 7004);
		
		// UDP connections
		
		// h3 ---> h4
		setUDPconnection(H, i_H4R2, i_H3R1, 2, 3, bufferSize, 7005);
		
		// h3 ---> h1
		Ptr<MyApp> udpApp = setUDPconnection(H, i_H1R1, i_H3R1, 2, 0, bufferSize, 7006);
		
		FlowMonitorHelper flowmn;
		Ptr<FlowMonitor> fmonitor_ptr = flowmn.InstallAll();
		
		// varying UDP Rate
		if(flag == 1)
		{
			Simulator::Schedule(Seconds(2.0), &IncRate, udpApp, DataRate("30Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(3.0), &IncRate, udpApp, DataRate("40Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(4.0), &IncRate, udpApp, DataRate("50Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(5.0), &IncRate, udpApp, DataRate("60Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(6.0), &IncRate, udpApp, DataRate("70Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(7.0), &IncRate, udpApp, DataRate("80Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(8.0), &IncRate, udpApp, DataRate("90Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(9.0), &IncRate, udpApp, DataRate("100Mbps"), &flowmn, fmonitor_ptr);
			Simulator::Schedule(Seconds(10.0), &IncRate, udpApp, DataRate("110Mbps"), &flowmn, fmonitor_ptr);
		}
		
		

		Simulator::Stop(Seconds(10));
		Simulator::Run();
		
		fmonitor_ptr->CheckForLostPackets();
		
		// Identifies the source and destination IP addresses
		Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmn.GetClassifier());
		
		// Moniters flows through different links
		std::map<FlowId, FlowMonitor::FlowStats> Stats = fmonitor_ptr->GetFlowStats();
		
		double sumFlow = 0, sumFlowSquare = 0;
		double tcpTP = 0, udpTP = 0;
		
		for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator itr = Stats.begin(); itr != Stats.end(); itr++)
		{
			Ipv4FlowClassifier::FiveTuple ft = classifier->FindFlow(itr->first);
			
			//Calculate the throughput of the flow
			double throughPut = itr->second.rxBytes * 8.0 /(itr->second.timeLastRxPacket.GetSeconds() - itr->second.timeFirstTxPacket.GetSeconds())/(1024*1024);
			sumFlow += throughPut;
			sumFlowSquare += throughPut * throughPut ;
			
			
			if(tcpSet.find(std::make_pair(ft.sourceAddress, ft.destinationAddress)) != tcpSet.end())
			{
				tcpTP += throughPut;
			}
			if(udpSet.find(std::make_pair(ft.sourceAddress, ft.destinationAddress)) != udpSet.end())
			{ 
				udpTP += throughPut;
			}
			
		}
		double FairnessIndex =(sumFlow * sumFlow)/(6 * sumFlowSquare);
		
		// Adding to the dataset
		if(flag == 0)
		{
			uint bs = bufferSize/packetSize;
			DataFairvBS.Add(bs, FairnessIndex);
			DatatcpTPvBS.Add(bs, tcpTP);
			DataudpTPvBS.Add(bs, udpTP);
			std::cout<<"Varying Buffer Size. Current Size: "<<bufferSize/packetSize<<"\n";
			std::cout<<"TCP TP: "<<tcpTP<<" UDP TP: "<<udpTP<<" Fairness: "<<FairnessIndex<<std::endl;
		
			// Updating buffer Size
			if(bs < 100)
			{
				bufferSize += 15*packetSize;
			}
			else {
				bufferSize = bufferSize + 100*packetSize;
			}
		}
		flag = 0;
		
		Simulator::Destroy();
		
	}
	
	// Generate plt files
	
	for(int i=0;i<4;i++)
	{
		std::string label = "graph";
		label = label + std::to_string(i+1);
		std::string title = "TCP Throughput ";
		title = title + std::to_string(i+1);
		title += " vs UDP Rate";
		
		getPlot(label, title, "UDP Rate(Mbps)", "Throughput(Mbps)", "set xrange [10:100]", dataiTCPvR[i]);
	}
	
	for(int i=0;i<2;i++)
	{
		std::string label = "graph";
		label = label + std::to_string(i+5);
		std::string title = "UDP Throughput ";
		title = title + std::to_string(i+1);
		title += " vs UDP Rate";
		
		getPlot(label, title, "UDP Rate(Mbps)", "Throughput(Mbps)", "set xrange [10:100]", dataiUDPvR[i]);
	}
	getPlot("TCPTPvRate", "TCP Throughput vs UDP Rate", "UDP Rate(Mbps)", "Throughput(Mbps)", "set xrange [10:100]", datatcpTPvR);
	getPlot("UDPTPvRate", "UDP Throughput vs UDP Rate", "UDP Rate(Mbps)", "Throughput(Mbps)", "set xrange [10:100]", dataudpTPvR);
	
	getPlot("FairnessvBS", "Fairness vs Buffer Size", "Buffer Size(no. of packets)", "Fairness", "set xrange [0:800]", DataFairvBS);
	getPlot("TCPTPvBS", "TCP Throughput vs Buffer Size", "Buffer Size(no. of packets)", "Throughput(Mbps)", "set xrange [0:800]", DatatcpTPvBS);
	getPlot("UDPTPvBS", "UDP Throughput vs Buffer Size", "Buffer Size(no. of packets)", "Throughput(Mbps)", "set xrange [0:800]", DataudpTPvBS);
	
	return 0;
	
}
		
void setTCPconnection(NodeContainer &H, Ipv4InterfaceContainer &iface, Ipv4InterfaceContainer &iface1, int source, int sink, int bufferSize, int port)
{
	uint16_t sinkPort = port;
	
	// Configure Sink
	Address sinkAddress(InetSocketAddress(iface.GetAddress(0), sinkPort));
	PacketSinkHelper PSH("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), sinkPort));
	ApplicationContainer appCont = PSH.Install(H.Get(sink));
	
	appCont.Start(Seconds(0));
	appCont.Stop(Seconds(10));
	
	// Configure Socket
	Ptr<Socket> socket = Socket::CreateSocket(H.Get(source), TcpSocketFactory::GetTypeId());
	socket->SetAttribute("SndBufSize", ns3::UintegerValue(bufferSize));
	socket->SetAttribute("RcvBufSize", ns3::UintegerValue(bufferSize));
	
	// Configure Application on source
	Ptr<MyApp> app = CreateObject<MyApp>();
	app->Setup(socket, sinkAddress, packetSize, 1000000, DataRate("20Mbps"));
	H.Get(source)->AddApplication(app);
	
	app->SetStartTime(Seconds(1));
	app->SetStopTime(Seconds(10));
	
	tcpSet[std::make_pair(iface1.GetAddress(0), iface.GetAddress(0))] = n_tcp++;
	
}

Ptr<MyApp> setUDPconnection(NodeContainer &H, Ipv4InterfaceContainer &iface, Ipv4InterfaceContainer &iface1, int source, int sink, int bufferSize, int port)
{
	uint16_t sinkPort = port;
	
	// Configure Sink
	Address sinkAddress(InetSocketAddress(iface.GetAddress(0), sinkPort));
	PacketSinkHelper PSH("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), sinkPort));
	ApplicationContainer appCont = PSH.Install(H.Get(sink));
	
	appCont.Start(Seconds(0));
	appCont.Stop(Seconds(10));
	
	// Configure Socket
	Ptr<Socket> socket = Socket::CreateSocket(H.Get(source), UdpSocketFactory::GetTypeId());
	socket->SetAttribute("RcvBufSize", ns3::UintegerValue(bufferSize));
	
	// Configure Application on source
	Ptr<MyApp> app = CreateObject<MyApp>();
	app->Setup(socket, sinkAddress, packetSize, 1000000, DataRate("20Mbps"));
	H.Get(source)->AddApplication(app);
	
	app->SetStartTime(Seconds(1));
	app->SetStopTime(Seconds(10));
	
	udpSet[std::make_pair(iface1.GetAddress(0), iface.GetAddress(0))] = n_udp++;
	
	return app;
}

void IncRate(Ptr<MyApp> app, DataRate newRate, FlowMonitorHelper *flowMonitorHelp, Ptr<FlowMonitor> flowMonitor)
{
	app->setRate(newRate);
	
	std::cout<<"Varying UDP rate. Current Rate: "<<curRate<<" Mbps\n";
	Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowMonitorHelp->GetClassifier());
	std::map<FlowId, FlowMonitor::FlowStats> Stats = flowMonitor->GetFlowStats();

	double tcpTP = 0, udpTP = 0;
	
	// Store individual connection throughput
	double throughputTCP[4] = {0}, throughputUDP[2] = {0};
	
	for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator itr = Stats.begin(); itr != Stats.end(); itr++)
	{
		Ipv4FlowClassifier::FiveTuple ft = classifier->FindFlow(itr->first);
		
		//Calculate the throughput of the flow
		double throughPut = itr->second.rxBytes * 8.0 /(itr->second.timeLastRxPacket.GetSeconds() - itr->second.timeFirstTxPacket.GetSeconds())/(1024*1024);

		if(tcpSet.find(std::make_pair(ft.sourceAddress, ft.destinationAddress)) != tcpSet.end())
		{
			tcpTP += throughPut;
			throughputTCP[tcpSet[std::make_pair(ft.sourceAddress, ft.destinationAddress)]] += throughPut;
		}
		if(udpSet.find(std::make_pair(ft.sourceAddress, ft.destinationAddress)) != udpSet.end())
		{ 
			udpTP += throughPut;
			throughputUDP[udpSet[std::make_pair(ft.sourceAddress, ft.destinationAddress)]] += throughPut;
		}
	}
	
	for(int i=0;i<4;i++)
	{
		dataiTCPvR[i].Add(curRate, throughputTCP[i]);
		std::cout<<throughputTCP[i]<<" ";
	}
	std::cout<<"Total TCP TP: "<< tcpTP << std::endl;
	for(int i=0;i<2;i++)
	{
		dataiUDPvR[i].Add(curRate, throughputUDP[i]);
		std::cout<<throughputUDP[i]<<" ";
	}
	std::cout<<"Total UDP TP: "<< udpTP << std::endl;
	
	datatcpTPvR.Add(curRate, tcpTP);
	dataudpTPvR.Add(curRate, udpTP);
	
	
	curRate += 10; 
	return;
}

void makeDataSet(Gnuplot2dDataset &dataset, std::string name)
{
	dataset.SetTitle("Name");
	dataset.SetStyle(Gnuplot2dDataset::LINES_POINTS);
} 

void getPlot(std::string fname, std::string title, std::string legendx, std::string legendy, std::string extra, Gnuplot2dDataset &dataset)
{
	std::ofstream plotFile((fname + ".plt").c_str());
	Gnuplot plot(fname + ".png");
	plot.SetTitle(title);
	plot.SetTerminal("png");
	plot.AppendExtra(extra);
	plot.SetLegend(legendx, legendy);
	plot.AddDataset(dataset);
	plot.GenerateOutput(plotFile);
	plotFile.close();
	return;
}