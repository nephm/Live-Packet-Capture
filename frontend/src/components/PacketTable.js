import React, { useState } from 'react';
import '../App.css';

//Colors for charts
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

function PacketTable({stats, recentPackets}) {
    const [open, setOpen] = useState(false);

    const triggerDownload = async (limit) => {
        try{
            const url = limit ? `/api/export_csv?limit=${limit}` : '/api/export_csv';
            const res = await fetch(url);
            if(!res.ok) return;
            const blob = await res.blob();
            const href = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = href;
            a.download = 'packets.csv';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(href);
        }catch(e){
            console.error('Export failed', e);
        } finally {
            setOpen(false);
        }
    };

    return(
        <>
        {/* Top Sources Tables */}
        <section className='tables-grid'>
            <div className='table-card'>
                <h3>Top Sources</h3>
                <div className='table-container'>
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Packets</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(stats.top_sources || []).slice(0, 5).map(([ip, count], index) =>(
                                <tr key={index}>
                                    <td className='ip-cell'>{ip}</td>
                                     <td className='count-cell'>{count}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            <div className='table-card'>
                <h3>Top Destinations</h3>
                <div className='table-container'>
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Packets</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(stats.top_destinations || []).slice(0, 5).map(([ip, count], index) =>(
                                <tr key={index}>
                                    <td className='ip-cell'>{ip}</td>
                                     <td className='count-cell'>{count}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        {/* Recent Packets Table */}
        <section className='recent-packets'>
            <div className='table-card full-width'>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3>Recent Packets</h3>
                    <div style={{ position: 'relative' }}>
                        <button onClick={() => setOpen(v => !v)} className='btn-export'>Export data ▾</button>
                        {open && (
                            <div className='export-menu'>
                                <button onClick={() => triggerDownload(null)} className='export-item'>Export all</button>
                                <button onClick={() => triggerDownload(1000)} className='export-item'>Export last 1000 packets</button>
                                <button onClick={() => triggerDownload(10000)} className='export-item'>Export last 10000 packets</button>
                            </div>
                        )}
                    </div>
                </div>
                <div className='table-container scrollable'>
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Protocol</th>
                                <th>Source Port</th>
                                <th>Destination Port</th>
                                <th>Size (bytes)</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recentPackets.map((packet, index) =>(
                                <tr key={index}>
                                    <td>{packet.time}</td>
                                    <td className='ip-cell'>{packet.src}</td>
                                    <td className='ip-cell'>{packet.dst}</td>
                                    <td>
                                        <span className='protocol-badge'
                                        style={{backgroundColor: PROTO_COLORS[packet.protocol] || PROTO_COLORS['OTHER']}}>
                                            {packet.protocol}
                                        </span>
                                    </td>
                                    <td>{packet.sport || 'N/A'}</td>
                                    <td>{packet.dport || 'N/A'}</td>
                                    <td>{packet.size}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </section>
        </>
    );
}

export default PacketTable;
