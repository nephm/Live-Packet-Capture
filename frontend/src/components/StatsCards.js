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
        </section>
    );
}

export default StatsCards;