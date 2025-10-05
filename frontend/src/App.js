import React from 'react';
import './App.css';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './components/Dashboard';

function App() {

  return (
    <BrowserRouter>
      <div className="App">
        <Routes>
          <Route path="/network" element={<Dashboard />} />
          <Route path="/" element={<Home />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;

function Home() {
  return (
    <div style={{ padding: 24 }}>
      <h1>dummy site</h1>
      <p>this is for test</p>
      <p><Link to="/network">go to network</Link></p>
    </div>
  );
}

