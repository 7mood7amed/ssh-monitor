import React, { useState, useEffect } from "react";

function Header() {

    const [lastUpdated, setLastUpdated] = useState(new Date().toLocaleTimeString());

    // Auto-update timestamp every 10 seconds
    useEffect(() => {
        const timer = setInterval(() => {
            setLastUpdated(new Date().toLocaleTimeString());
        }, 10000);
        return () => clearInterval(timer);
    }, []);

    return (
        <header className="header">
            <h1>🧠 Raven Security Dashboard</h1>
            <p>Real-time File & Directory Activity Monitoring</p>
            <p>
                <i className="fas fa-clock"></i> 🔄 Last Updated: {lastUpdated}
            </p>
        </header>
    );
}

export default Header;
