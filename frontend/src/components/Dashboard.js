import React, {useEffect, useState, useRef} from 'react';
import '../App.css';
import StatsCards from './StatsCards';
import PacketTable from './PacketTable';
import Charts from './Charts';


function Dashboard() {
    const [stats, setStats] = useState({
        totalPackets: 0,
        packets_sent: 0,
        packets_received: 0,
        unique_IPs: 0,
        bytes_sent: 0,
        bytes_received:0,
        protocols_count: {},
        top_sources: [],
        top_destinations: [],
        uptime_seconds: 0,
        packets_per_second: 0
    });

    const [recentPackets, setRecentPackets] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [packetHistory, setPacketHistory] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [lastUpdate, setlastUpdate] = useState(new Date());
    const lastTotalRef = useRef(0);

    // Fetch stats from backend
    const fetchStats = async () => {
    	try {
            const res = await fetch('/api/stats');
            if (res.ok){
                const data = await res.json();
                const normalized = {
                    totalPackets: data.total_packets,
                    packets_sent: data.packets_sent,
                    packets_received: data.packets_received,
                    filtered_packets: data.filtered_packets,
                    unique_ips: data.unique_ips,
                    bytes_sent: data.bytes_sent,
                    bytes_received: data.bytes_received,
                    protocols_count: data.protocol_breakdown,
                    top_sources: data.top_sources,
                    top_destinations: data.top_destinations,
                    top_ports: data.top_ports,
                    uptime_seconds: data.uptime_seconds,
                    packets_per_second: data.packets_per_second,
                    avg_packet_size: data.avg_packet_size,
                    min_packet_size: data.min_packet_size,
                    max_packet_size: data.max_packet_size,
                    active_connections: data.active_connections,
                    total_alerts: data.total_alerts
                };
                setStats(normalized);
                setIsConnected(true);

                const curr = new Date();
                const delta = Math.max(0, (normalized.totalPackets || 0) - (lastTotalRef.current || 0));
                lastTotalRef.current = normalized.totalPackets || 0;
                setPacketHistory(prev => {
                    const newHistory = [ ...prev,{
                        time: curr.toLocaleTimeString(),
                        packets: delta,
                        timestamp: curr.getTime()
                    }];
                    return newHistory.slice(-60);
                });

                setlastUpdate(curr);
            } else{
                setIsConnected(false);
            }
        } catch (error) {
            console.error('Error fetching stats:', error);
            setIsConnected(false);
        }
    }

    //fetch recent packets from backend
    const fetchRecentPackets = async () =>{
    	try {
            const res = await fetch('/api/events');
            if (res.ok){
                const data = await res.json();
                setRecentPackets(data.slice(0, 20));
            } else{
                console.error('Failed to fetch packets', res.status);
            }
        } catch (error) {
            console.error('Error fetching packets', error);
            
        }
    };

    const fetchAlerts = async () =>{
        try{
            const res = await fetch('/api/alerts?limit=5');
            if(res.ok){
                const data = await res.json();
                setAlerts(data);
            }
        }catch(err){
            console.error('Error fetching alerts', err);
        }
    }

    // set real-time updates
    useEffect(()=>{

        fetchStats();
        fetchRecentPackets();
        fetchAlerts();

        const statInterval = setInterval(() =>{
            fetchStats();   
            fetchRecentPackets();
            fetchAlerts();
        }, 1000); //everysecond

        return () =>{
            clearInterval(statInterval);
        };
    }, []);

    return(
        <>
        <header className='app-header'>
            <h1>🌐 Network Packet Analyzer</h1>
            <div className='connection-status'>
                <span className={`status-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
                    {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
                </span>
                <span className="last-updated">
                    Last Updated: {lastUpdate.toLocaleTimeString()}
                </span>

            </div>
            {alerts.length > 0 && (
                <div className='alert-banner'>
                    <span>Alert: {alerts[0].type} - {alerts[0].severity}</span>
                </div>
            )}
        </header>
        
        <main className='dashboard'>
                <StatsCards stats={stats} />
                <Charts
                    stats={stats}
                    packetHistory={packetHistory} />
                <PacketTable
                    stats={stats}
                    recentPackets={recentPackets} />
        </main></>
    );
}

export default Dashboard;
