import React from 'react';
import './App.css';

import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, PieChart, Pie, Cell, LineChart, Line, ResponsiveContainer   
} from 'recharts';

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

function Chart({stats, packetHistory}) {

    const protocolData = Object.entries(stats.protocols_count).map(([protocol, count]) => ({
        name: protocol,
        value: count,
        color: PROTOCOL_COLORS[protocol] || '#95a5a6'
    }));

    //top sources data for bar chart
    const topSources = (stats.top_sources || []).slice(0, 5).map(([ip, count]) => ({
        ip: ip.length > 15 ? ip.subString(0, 12) + '...' : ip,
        fullIp: ip,
        packets: count
    }));

    return(
        <section className='charts-grid'>
            {/* Real-Time Packet Flow Chart*/}
            <div className='chart-card'>
                <h3>Real-Time Packet Flow</h3>
                <ResponsiveContainer width="100%" height={250}>
                    <LineChart data={packetHistory}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis />
                        <Tooltip />
                        <Line 
                        type="monotone" 
                        dataKey="packets" 
                        stroke="#3498db" 
                        strokeWidth={2}
                        dot={{ fill: '#3498db', strokeWidth: 2, r: 4 }}
                        />
                    </LineChart>
                </ResponsiveContainer>
            </div>

            {/* Protocol Distribution Pie Chart */}
            <div className='chart-card'>
                <h3> Protocol Distribution</h3>
                <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                        <Pie
                            data={protocolData}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                            outerRadius={80}
                            fill="#8884d8"
                            dataKey="value"
                        >
                            {protocolData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                        </Pie>
                        <Tooltip />
                    </PieChart>
                </ResponsiveContainer>
            </div>

            {/* Top Sources Bar Chart*/}
            <div className='chart-card'>
                <h3>📊 Top 5 Source IPs</h3>
                <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={topSources} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="ip" />
                        <YAxis />
                        <Tooltip 
                            labelformatter={(value) => {
                                const item = topSources.find(d => d.ip === value);
                                return item ? item.fullIp : value;
                            }} 
                            />
                        <Bar dataKey="packets" fill="#2ecc71" />
                    </BarChart>
                </ResponsiveContainer>
            </div>
        </section>
    );
}

export default Charts;
