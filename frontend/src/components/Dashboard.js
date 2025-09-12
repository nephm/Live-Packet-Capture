import React, {useEffect, useState} from 'react';
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
    const [packetHistory, setPacketHistory] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [lastUpdate, setlastUpdate] = useState(new Date());

    // Fetch stats from backend
    const fetchStats = async () => {
        try {
            const res = await fetch('https://localhost:8000/stats', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json',} 
            });
            if (res.ok){
                const data = await res.json();
                setStats(data);
                setIsConnected(true);

                //add curr packet count to history for charts
                const curr = new Date();
                setPacketHistory(prev => {
                    const newHistory = [ ...prev,{
                        time: curr.toLocaleTimeString(),
                        packets: data.totalPackets,
                        timestamp: curr.getTime()
                    }];
                    //keep only last 20 data
                    return newHistory.slice(-20);
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
            const res = await fetch('https://localhost:8000/events', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json',} 
            });
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

    // set real-time updates
    useEffect(()=>{

        fetchStats();
        fetchRecentPackets();

        const statInterval = setInterval(() =>{
            fetchStats();   
            fetchRecentPackets();
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
                <span clasName="last-updated">
                    Last Updated: {lastUpdate.toLocaleTimeString()}
                </span>

            </div>
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
