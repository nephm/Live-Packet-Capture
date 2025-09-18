import React from 'react';
import '../App.css';

//colors for charts
const PROTO_COLORS = {
    TCP: '#8884d8',
    UDP: '#e74c3c',
    HTTP: '#2ecc71',
    HTTPS: '#f39c12',
    ICMP: '#e67e22',
    DNS: '#9b59b6',
    SSH: '#329c',
    OTHER: '#95a5a6'
};

function StatsCards({stats}){
    //format bytes to KB, MB, GB
    const formatBytes = (bytes) => {
        if(bytes ===0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes)/ Math.log(k));
        return parseFloat((bytes / Math.pow(k,i)).toFixed(2)) + ' ' + sizes[i];
    };

    //format uptime
    const formatUptime = (seconds) =>{
        const hrs = Math.floor(seconds)/ 3600;
        const mins = Math.floor(seconds % 3600)/60;
        const secs = seconds % 60;
        return `${hrs}h ${mins}m ${secs}s`;
    };

    return (
        
        <section className='stats-grid'>
            <div className="stat-card">
                <h3>General Statistics</h3>
                <div className='stat-item'>
                    <span className='stat-label'>Total Packets:</span>
                    <span className='stat-value'>{stats?.totalPackets?.toLocaleString() ?? "0"}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Packets Sent:</span>
                    <span className='stat-value'>{stats?.packets_sent?.toLocaleString() ?? "0"}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Packets Received:</span>
                    <span className='stat-value'>{stats?.packets_received?.toLocaleString() ?? "0"}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Packets/Second:</span>
                    <span className='stat-value'>{stats?.packets_per_second?.toFixed(2) ?? "0.00"}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Uptime:</span>
                    <span className='stat-value'>{stats?.uptime_seconds ? formatUptime(stats.uptime_seconds) : "0s"}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Unique IPs:</span>
                    <span className='stat-value'>{stats?.unique_ips ?? 0}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Bytes Sent:</span>
                    <span className='stat-value'>{stats?.bytes_sent ? formatBytes(stats.bytes_sent) : "0 B"}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Bytes Received:</span>
                    <span className='stat-value'>{stats?.bytes_received ? formatBytes(stats.bytes_received) : "0 B"}</span>
                </div>
            </div>

            <div className="stat-card">
                <h3>Protocol Distribution</h3>
                <div className='protocol-list'>
                    {stats?.protocols_count ? Object.entries(stats.protocols_count).map(([proto, count]) => (
                        <div key={proto} className='protocol-item'>
                            <span className='protocol-name' style={{color: PROTO_COLORS[proto]}}>
                                {proto}:
                            </span>
                            <span className='protocol-count'>{count}</span>
                        </div>
                    )) : <p>no protocol data</p>}
                </div>
            </div>
        </section>
    );
}

export default StatsCards;
