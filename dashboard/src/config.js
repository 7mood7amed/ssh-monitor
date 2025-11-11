// const getApiBaseUrl = async () => {
//     try {
//         // Try to fetch the backend’s self-reported IP
//         const res = await fetch("http://localhost:5000/api/hostinfo", { mode: "cors" });
//         const data = await res.json();

//         // Use the backend IP if available, otherwise fall back to localhost
//         if (data.ip) return `http://${data.ip}:5000`;
//     } catch (err) {
//         console.warn("Auto IP detection failed, using localhost");
//     }
//     return "http://localhost:5000";
// };

// export default getApiBaseUrl;
