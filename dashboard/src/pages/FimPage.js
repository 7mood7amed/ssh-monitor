import React from "react";
import FimEvents from "../components/FimEvents";

export default function FimPage({ refreshTrigger }) {
  return (
    <div className="page">
      <FimEvents refreshTrigger={refreshTrigger} />
    </div>
  );
}
