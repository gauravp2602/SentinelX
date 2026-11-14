
// ==========================================
// CYBERSENTINEL SOC - DASHBOARD CHARTS
// ==========================================

const severityCanvas = document.getElementById("severityChart");

if (severityCanvas && window.Chart) {
    new Chart(severityCanvas, {
        type: "doughnut",

        data: {
            labels: ["Critical", "High", "Medium", "Low", "Info"],

            datasets: [{
                data: sevData,
                backgroundColor: [
                    "#ff5364",
                    "#ff9c50",
                    "#f4c15d",
                    "#39c9a2",
                    "#6c8cff"
                ],
                borderWidth: 0,
                hoverOffset: 8,
                spacing: 3
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "72%",

            plugins: {
                legend: {
                    display: false
                },

                tooltip: {
                    backgroundColor: "#101d2d",
                    titleColor: "#ffffff",
                    bodyColor: "#dce8f2",
                    padding: 12,
                    cornerRadius: 8
                }
            }
        }
    });
}


// ==========================================
// 7 DAY SECURITY ACTIVITY
// ==========================================

const trendCanvas = document.getElementById("trendChart");

if (trendCanvas && window.Chart) {
    new Chart(trendCanvas, {
        type: "line",

        data: {
            labels: trendLabels,

            datasets: [{
                label: "Security Events",
                data: trendCounts,

                borderColor: "#ff9c50",
                backgroundColor: "rgba(255,156,80,0.12)",

                borderWidth: 2,
                fill: true,
                tension: 0.4,

                pointRadius: 4,
                pointHoverRadius: 7,
                pointBackgroundColor: "#ff9c50",
                pointBorderColor: "#101d2d",
                pointBorderWidth: 2
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            interaction: {
                intersect: false,
                mode: "index"
            },

            plugins: {
                legend: {
                    display: false
                },

                tooltip: {
                    backgroundColor: "#101d2d",
                    titleColor: "#ffffff",
                    bodyColor: "#dce8f2",
                    padding: 12,
                    cornerRadius: 8
                }
            },

            scales: {
                x: {
                    grid: {
                        display: false
                    },

                    ticks: {
                        color: "#8194a7",
                        font: {
                            size: 10
                        }
                    },

                    border: {
                        display: false
                    }
                },

                y: {
                    beginAtZero: true,

                    ticks: {
                        precision: 0,
                        color: "#8194a7",
                        font: {
                            size: 10
                        }
                    },

                    grid: {
                        color: "rgba(129,148,167,0.10)"
                    },

                    border: {
                        display: false
                    }
                }
            }
        }
    });
}
