import React from 'react';


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
    const formatUpttime = (seconds) =>{
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
                    <span className='stat-value'>{stats.total_packets.toLocaleString()}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Packets Sent:</span>
                    <span className='stat-value'>{stats.packets_sent.toLocaleString()}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Packets Received:</span>
                    <span className='stat-value'>{stats.packets_received.toLocaleString()}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Packets/Second:</span>
                    <span className='stat-value'>{stats.packets_per_second.toFixed(2)}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Uptime:</span>
                    <span className='stat-value'>{formatUpttime(stats.uptime_seconds)}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Unique IPs:</span>
                    <span className='stat-value'>{stats.unique_ips}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Bytes Sent:</span>
                    <span className='stat-value'>{formatBytes(stats.bytes_sent)}</span>
                </div>
                <div className='stat-item'>
                    <span className='stat-label'>Bytes Received:</span>
                    <span className='stat-value'>{formatUpttime(stats.bytes_received)}</span>
                </div>
            </div>

            <div className="stat-card">
                <h3>Protocol Distribution</h3>
                <div className='protocol-list'>
                    {Object.entries(stats.protocols_count).map(([proto, count]) => (
                        <div key={proto} className='protocol-item'>
                            <span className='protocol-name' style={{color: PROTO_COLORS[proto]}}>
                                {proto}:
                            </span>
                            <span className='protocol-count'>{count}</span>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}

export default StatsCards;
