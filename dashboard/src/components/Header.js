import React from "react";
import "./Header.css";

function Header(){
    return (
        <header className="dashboard-header">
            <h1>Raven Monitoring Dashboard</h1>
            <p className="subtitle">Real-Time Log & Agent Activity Tracker </p>
        </header>
    );
}

export default Header;