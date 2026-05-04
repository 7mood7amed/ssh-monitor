import React, { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Header from "./components/Header";
import Footer from "./components/Footer";

import OverviewPage from "./pages/OverviewPage";
import SshLogsPage from "./pages/SshLogsPage";
import WebTrafficPage from "./pages/WebTrafficPage";
import FtpLogsPage from "./pages/FtpLogsPage";
import AlertsPage from "./pages/AlertsPage";
import NmapPage from "./pages/NmapPage";
import AIInsights from "./components/AIInsights";
import NetworkEvents from "./pages/NetworkEvents";

import "./App.css";

function App() {
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [lastUpdated, setLastUpdated] = useState(new Date().toLocaleTimeString());
  const REFRESH_INTERVAL_MS = 30000;

  useEffect(() => {
    const interval = setInterval(() => {
      setRefreshTrigger((v) => v + 1);
      setLastUpdated(new Date().toLocaleTimeString());
    }, REFRESH_INTERVAL_MS);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app">
      <Header lastUpdated={lastUpdated} />
      <main>
        <Routes>
          <Route path="/" element={<OverviewPage refreshTrigger={refreshTrigger} />} />
          <Route path="/ssh" element={<SshLogsPage refreshTrigger={refreshTrigger} />} />
          <Route path="/web" element={<WebTrafficPage refreshTrigger={refreshTrigger} />} />
          <Route path="/ftp" element={<FtpLogsPage refreshTrigger={refreshTrigger} />} />
          <Route path="/alerts" element={<AlertsPage refreshTrigger={refreshTrigger} />} />
          <Route path="/nmap" element={<NmapPage />} />
          <Route path="/ai" element={<AIInsights refreshTrigger={refreshTrigger} />} />
          <Route path="/network-events" element={<NetworkEvents />} />

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}

export default App;